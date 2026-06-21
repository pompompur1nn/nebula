use std::collections::BTreeSet;
use std::fmt;

pub type PublicRecord = ReplayPublicRecord;
pub type Runtime = ReplayLaneRuntime;
pub type Result<T> = std::result::Result<T, ReplayError>;

const MODULE_ID: &str = "monero-l2-pq-bridge-exit-force-exit-wave105-credit-accounting-replay-lane";
const WAVE104_BINDING: &str = "wave104-relay-confirmation-reorg-binding";
const FAIL_CLOSED_RELEASE: &str = "release_credit_allowed: false";
const FAIL_CLOSED_ACCOUNTING: &str = "credit_accounting_allowed: false";
const FAIL_CLOSED_HEAVY_GATE: &str = "heavy_gates_ran: false";
const ROOT_PREFIX: &str = "w105";
const MIN_SIGNOFFS: usize = 5;
const MIN_HEAVY_GATE_EVIDENCE: usize = 3;
const MIN_CONFIRMATION_DEPTH: u64 = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub lane_id: String,
    pub wave_id: u64,
    pub min_confirmation_depth: u64,
    pub min_signoffs: usize,
    pub min_heavy_gate_evidence: usize,
    pub require_live_feed: bool,
    pub require_pq_authorization: bool,
    pub require_fee_rebate_netting: bool,
    pub require_beneficiary_match: bool,
    pub require_reserve_balance: bool,
    pub require_circuit_breakers_clear: bool,
}

impl Config {
    pub fn fail_closed() -> Self {
        Self {
            lane_id: MODULE_ID.to_string(),
            wave_id: 105,
            min_confirmation_depth: MIN_CONFIRMATION_DEPTH,
            min_signoffs: MIN_SIGNOFFS,
            min_heavy_gate_evidence: MIN_HEAVY_GATE_EVIDENCE,
            require_live_feed: true,
            require_pq_authorization: true,
            require_fee_rebate_netting: true,
            require_beneficiary_match: true,
            require_reserve_balance: true,
            require_circuit_breakers_clear: true,
        }
    }

    pub fn devnet() -> Self {
        Self {
            min_confirmation_depth: 12,
            min_signoffs: 6,
            min_heavy_gate_evidence: 4,
            ..Self::fail_closed()
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("lane_id", &self.lane_id)?;
        if self.wave_id != 105 {
            return Err(ReplayError::InvalidConfig(
                "wave id must remain bound to Wave 105".to_string(),
            ));
        }
        if self.min_confirmation_depth < MIN_CONFIRMATION_DEPTH {
            return Err(ReplayError::InvalidConfig(
                "confirmation depth below release floor".to_string(),
            ));
        }
        if self.min_signoffs < MIN_SIGNOFFS {
            return Err(ReplayError::InvalidConfig(
                "signoff quorum below release floor".to_string(),
            ));
        }
        if self.min_heavy_gate_evidence < MIN_HEAVY_GATE_EVIDENCE {
            return Err(ReplayError::InvalidConfig(
                "heavy gate evidence below release floor".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::fail_closed()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub config: Config,
    pub sequence: ReplaySequence,
    pub verdict: ReplayVerdict,
    pub public_record: PublicRecord,
}

impl State {
    pub fn new(config: Config, sequence: ReplaySequence) -> Result<Self> {
        config.validate()?;
        let mut runtime = ReplayLaneRuntime::new(config, sequence)?;
        runtime.evaluate();
        Ok(runtime.into_state())
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        self.sequence.validate()?;
        self.verdict.validate_fail_closed_text()?;
        if self.public_record.state_root != state_root(self) {
            return Err(ReplayError::RootMismatch(
                "public record state root does not match state".to_string(),
            ));
        }
        Ok(())
    }

    pub fn release_credit_allowed(&self) -> bool {
        self.verdict.release_credit_allowed
    }

    pub fn credit_accounting_allowed(&self) -> bool {
        self.verdict.credit_accounting_allowed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayLaneRuntime {
    config: Config,
    sequence: ReplaySequence,
    verdict: ReplayVerdict,
}

impl ReplayLaneRuntime {
    pub fn new(config: Config, sequence: ReplaySequence) -> Result<Self> {
        config.validate()?;
        sequence.validate()?;
        Ok(Self {
            config,
            sequence,
            verdict: ReplayVerdict::fail_closed("runtime constructed without evaluation"),
        })
    }

    pub fn evaluate(&mut self) {
        self.verdict = evaluate_sequence(&self.config, &self.sequence);
    }

    pub fn verdict(&self) -> &ReplayVerdict {
        &self.verdict
    }

    pub fn sequence(&self) -> &ReplaySequence {
        &self.sequence
    }

    pub fn into_state(self) -> State {
        let mut state = State {
            config: self.config,
            sequence: self.sequence,
            verdict: self.verdict,
            public_record: ReplayPublicRecord::fail_closed("state assembly pending root"),
        };
        state.public_record = public_record(&state);
        state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplaySequence {
    pub sequence_id: String,
    pub wave104: Wave104Binding,
    pub relay_witness: RootBinding,
    pub confirmation_ladder: ConfirmationLadder,
    pub reorg_monitor: ReorgMonitor,
    pub credit_ledger: CreditLedgerDelta,
    pub beneficiary: BeneficiaryAccounting,
    pub fee_rebate: FeeRebateNetting,
    pub reserve: ReserveBalanceCheck,
    pub pq_authorization: PqAuthorization,
    pub circuit_breakers: CircuitBreakerSet,
    pub live_heavy_gate: LiveHeavyGateEvidence,
    pub signoffs: SignoffSet,
    pub replay_steps: Vec<ReplayStep>,
}

impl ReplaySequence {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("sequence_id", &self.sequence_id)?;
        self.wave104.validate()?;
        self.relay_witness.validate("relay_witness")?;
        self.confirmation_ladder.validate()?;
        self.reorg_monitor.validate()?;
        self.credit_ledger.validate()?;
        self.beneficiary.validate()?;
        self.fee_rebate.validate()?;
        self.reserve.validate()?;
        self.pq_authorization.validate()?;
        self.circuit_breakers.validate()?;
        self.live_heavy_gate.validate()?;
        self.signoffs.validate()?;
        validate_replay_steps(&self.replay_steps)?;
        Ok(())
    }

    pub fn devnet() -> Self {
        let claim_id = "force-exit-claim-devnet-105";
        let beneficiary_id = "beneficiary-account-devnet-105";
        Self {
            sequence_id: "wave105-replay-sequence-devnet".to_string(),
            wave104: Wave104Binding::devnet(),
            relay_witness: RootBinding::new(
                "relay-witness",
                root_for("relay-witness", claim_id),
                104,
                221_004,
            ),
            confirmation_ladder: ConfirmationLadder::devnet(claim_id),
            reorg_monitor: ReorgMonitor::devnet(claim_id),
            credit_ledger: CreditLedgerDelta::devnet(claim_id),
            beneficiary: BeneficiaryAccounting::devnet(beneficiary_id),
            fee_rebate: FeeRebateNetting::devnet(claim_id),
            reserve: ReserveBalanceCheck::devnet(claim_id),
            pq_authorization: PqAuthorization::devnet(claim_id),
            circuit_breakers: CircuitBreakerSet::devnet(),
            live_heavy_gate: LiveHeavyGateEvidence::devnet(claim_id),
            signoffs: SignoffSet::devnet(),
            replay_steps: devnet_replay_steps(claim_id),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Wave104Binding {
    pub binding_id: String,
    pub relay_witness_root: String,
    pub confirmation_ladder_root: String,
    pub reorg_monitor_root: String,
    pub release_receipt_root: String,
}

impl Wave104Binding {
    pub fn devnet() -> Self {
        Self {
            binding_id: WAVE104_BINDING.to_string(),
            relay_witness_root: root_for("wave104-relay", "force-exit-claim-devnet-105"),
            confirmation_ladder_root: root_for(
                "wave104-confirmation",
                "force-exit-claim-devnet-105",
            ),
            reorg_monitor_root: root_for("wave104-reorg", "force-exit-claim-devnet-105"),
            release_receipt_root: root_for(
                "wave104-release-receipt",
                "force-exit-claim-devnet-105",
            ),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("binding_id", &self.binding_id)?;
        require_root("relay_witness_root", &self.relay_witness_root)?;
        require_root("confirmation_ladder_root", &self.confirmation_ladder_root)?;
        require_root("reorg_monitor_root", &self.reorg_monitor_root)?;
        require_root("release_receipt_root", &self.release_receipt_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootBinding {
    pub domain: String,
    pub root: String,
    pub source_wave: u64,
    pub height: u64,
}

impl RootBinding {
    pub fn new(domain: &str, root: String, source_wave: u64, height: u64) -> Self {
        Self {
            domain: domain.to_string(),
            root,
            source_wave,
            height,
        }
    }

    pub fn validate(&self, field: &str) -> Result<()> {
        require_non_empty(field, &self.domain)?;
        require_root(field, &self.root)?;
        if self.source_wave < 104 {
            return Err(ReplayError::InvalidEvidence(format!(
                "{} source wave predates Wave 104",
                field
            )));
        }
        if self.height == 0 {
            return Err(ReplayError::InvalidEvidence(format!(
                "{} height must be non-zero",
                field
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmationLadder {
    pub ladder_root: String,
    pub claim_id: String,
    pub confirmed_depth: u64,
    pub observed_heights: Vec<u64>,
}

impl ConfirmationLadder {
    pub fn devnet(claim_id: &str) -> Self {
        Self {
            ladder_root: root_for("confirmation-ladder", claim_id),
            claim_id: claim_id.to_string(),
            confirmed_depth: 14,
            observed_heights: vec![221_000, 221_002, 221_004, 221_006, 221_008, 221_014],
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_root("ladder_root", &self.ladder_root)?;
        require_non_empty("claim_id", &self.claim_id)?;
        if self.confirmed_depth == 0 {
            return Err(ReplayError::InvalidEvidence(
                "confirmation depth must be non-zero".to_string(),
            ));
        }
        if self.observed_heights.len() < 2 {
            return Err(ReplayError::InvalidEvidence(
                "confirmation ladder needs multiple observed heights".to_string(),
            ));
        }
        validate_strictly_increasing("observed_heights", &self.observed_heights)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReorgMonitor {
    pub monitor_root: String,
    pub claim_id: String,
    pub max_reorg_depth: u64,
    pub competing_tip_count: u32,
    pub stable_window_observed: bool,
}

impl ReorgMonitor {
    pub fn devnet(claim_id: &str) -> Self {
        Self {
            monitor_root: root_for("reorg-monitor", claim_id),
            claim_id: claim_id.to_string(),
            max_reorg_depth: 1,
            competing_tip_count: 0,
            stable_window_observed: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_root("monitor_root", &self.monitor_root)?;
        require_non_empty("claim_id", &self.claim_id)?;
        if self.max_reorg_depth > 2 {
            return Err(ReplayError::InvalidEvidence(
                "reorg depth exceeds release monitor bound".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreditLedgerDelta {
    pub ledger_root_before: String,
    pub ledger_root_after: String,
    pub claim_id: String,
    pub debit_amount: u64,
    pub credit_amount: u64,
    pub fee_amount: u64,
    pub rebate_amount: u64,
    pub delta_entries: Vec<LedgerEntry>,
}

impl CreditLedgerDelta {
    pub fn devnet(claim_id: &str) -> Self {
        Self {
            ledger_root_before: root_for("credit-ledger-before", claim_id),
            ledger_root_after: root_for("credit-ledger-after", claim_id),
            claim_id: claim_id.to_string(),
            debit_amount: 10_000,
            credit_amount: 9_860,
            fee_amount: 180,
            rebate_amount: 40,
            delta_entries: vec![
                LedgerEntry::new("reserve-debit", "reserve", -10_000),
                LedgerEntry::new("beneficiary-credit", "beneficiary", 9_860),
                LedgerEntry::new("fee-vault-credit", "fee-vault", 180),
                LedgerEntry::new("rebate-offset", "rebate-vault", -40),
            ],
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_root("ledger_root_before", &self.ledger_root_before)?;
        require_root("ledger_root_after", &self.ledger_root_after)?;
        require_non_empty("claim_id", &self.claim_id)?;
        if self.ledger_root_before == self.ledger_root_after {
            return Err(ReplayError::InvalidEvidence(
                "ledger roots must change after accepted credit delta".to_string(),
            ));
        }
        let planned = self
            .debit_amount
            .saturating_sub(self.fee_amount)
            .saturating_add(self.rebate_amount);
        if planned != self.credit_amount {
            return Err(ReplayError::AccountingDenied(
                "credit amount does not match debit-fee+rebate netting".to_string(),
            ));
        }
        if self.delta_entries.len() < 4 {
            return Err(ReplayError::AccountingDenied(
                "ledger delta must include reserve, beneficiary, fee, and rebate entries"
                    .to_string(),
            ));
        }
        for entry in &self.delta_entries {
            entry.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerEntry {
    pub entry_id: String,
    pub account_id: String,
    pub amount: i128,
}

impl LedgerEntry {
    pub fn new(entry_id: &str, account_id: &str, amount: i128) -> Self {
        Self {
            entry_id: entry_id.to_string(),
            account_id: account_id.to_string(),
            amount,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("entry_id", &self.entry_id)?;
        require_non_empty("account_id", &self.account_id)?;
        if self.amount == 0 {
            return Err(ReplayError::AccountingDenied(
                "ledger delta entry cannot be zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeneficiaryAccounting {
    pub beneficiary_id: String,
    pub account_root_before: String,
    pub account_root_after: String,
    pub planned_credit: u64,
    pub observed_credit: u64,
    pub nullifier_bound: bool,
}

impl BeneficiaryAccounting {
    pub fn devnet(beneficiary_id: &str) -> Self {
        Self {
            beneficiary_id: beneficiary_id.to_string(),
            account_root_before: root_for("beneficiary-before", beneficiary_id),
            account_root_after: root_for("beneficiary-after", beneficiary_id),
            planned_credit: 9_860,
            observed_credit: 9_860,
            nullifier_bound: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("beneficiary_id", &self.beneficiary_id)?;
        require_root("account_root_before", &self.account_root_before)?;
        require_root("account_root_after", &self.account_root_after)?;
        if self.account_root_before == self.account_root_after {
            return Err(ReplayError::AccountingDenied(
                "beneficiary account root must reflect credit".to_string(),
            ));
        }
        if self.planned_credit != self.observed_credit {
            return Err(ReplayError::AccountingDenied(
                "beneficiary observed credit mismatch".to_string(),
            ));
        }
        if !self.nullifier_bound {
            return Err(ReplayError::AccountingDenied(
                "beneficiary credit lacks nullifier binding".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeRebateNetting {
    pub netting_root: String,
    pub claim_id: String,
    pub fee_amount: u64,
    pub rebate_amount: u64,
    pub net_fee: u64,
    pub fee_vault_bound: bool,
    pub rebate_vault_bound: bool,
}

impl FeeRebateNetting {
    pub fn devnet(claim_id: &str) -> Self {
        Self {
            netting_root: root_for("fee-rebate-netting", claim_id),
            claim_id: claim_id.to_string(),
            fee_amount: 180,
            rebate_amount: 40,
            net_fee: 140,
            fee_vault_bound: true,
            rebate_vault_bound: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_root("netting_root", &self.netting_root)?;
        require_non_empty("claim_id", &self.claim_id)?;
        if self.fee_amount < self.rebate_amount {
            return Err(ReplayError::AccountingDenied(
                "rebate exceeds fee amount".to_string(),
            ));
        }
        if self.fee_amount - self.rebate_amount != self.net_fee {
            return Err(ReplayError::AccountingDenied(
                "net fee does not match fee minus rebate".to_string(),
            ));
        }
        if !self.fee_vault_bound || !self.rebate_vault_bound {
            return Err(ReplayError::AccountingDenied(
                "fee and rebate vault roots must both be bound".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveBalanceCheck {
    pub reserve_root: String,
    pub reserve_account_id: String,
    pub balance_before: u64,
    pub reserved_liabilities: u64,
    pub release_amount: u64,
    pub balance_after: u64,
}

impl ReserveBalanceCheck {
    pub fn devnet(claim_id: &str) -> Self {
        Self {
            reserve_root: root_for("reserve-balance", claim_id),
            reserve_account_id: "monero-bridge-reserve-devnet".to_string(),
            balance_before: 1_000_000,
            reserved_liabilities: 400_000,
            release_amount: 10_000,
            balance_after: 990_000,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_root("reserve_root", &self.reserve_root)?;
        require_non_empty("reserve_account_id", &self.reserve_account_id)?;
        if self.balance_before < self.release_amount {
            return Err(ReplayError::ReserveDenied(
                "reserve balance cannot cover release amount".to_string(),
            ));
        }
        if self.balance_before - self.release_amount != self.balance_after {
            return Err(ReplayError::ReserveDenied(
                "reserve after balance mismatch".to_string(),
            ));
        }
        if self.balance_after < self.reserved_liabilities {
            return Err(ReplayError::ReserveDenied(
                "reserve after balance below liabilities".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqAuthorization {
    pub authorization_root: String,
    pub key_epoch: u64,
    pub scheme: PqScheme,
    pub quorum: u16,
    pub approvals: u16,
    pub replay_nonce: u64,
    pub transcript_bound: bool,
}

impl PqAuthorization {
    pub fn devnet(claim_id: &str) -> Self {
        Self {
            authorization_root: root_for("pq-authorization", claim_id),
            key_epoch: 105,
            scheme: PqScheme::HybridMlDsaSphincs,
            quorum: 4,
            approvals: 5,
            replay_nonce: 105_000_001,
            transcript_bound: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_root("authorization_root", &self.authorization_root)?;
        if self.key_epoch < 105 {
            return Err(ReplayError::AuthorizationDenied(
                "pq key epoch predates Wave 105".to_string(),
            ));
        }
        if self.approvals < self.quorum {
            return Err(ReplayError::AuthorizationDenied(
                "pq approvals below quorum".to_string(),
            ));
        }
        if self.replay_nonce == 0 {
            return Err(ReplayError::AuthorizationDenied(
                "pq replay nonce must be non-zero".to_string(),
            ));
        }
        if !self.transcript_bound {
            return Err(ReplayError::AuthorizationDenied(
                "pq authorization is not transcript bound".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PqScheme {
    MlDsa,
    SphincsPlus,
    Falcon,
    HybridMlDsaSphincs,
}

impl fmt::Display for PqScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MlDsa => write!(f, "ml-dsa"),
            Self::SphincsPlus => write!(f, "sphincs-plus"),
            Self::Falcon => write!(f, "falcon"),
            Self::HybridMlDsaSphincs => write!(f, "hybrid-ml-dsa-sphincs"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitBreakerSet {
    pub root: String,
    pub breakers: Vec<CircuitBreaker>,
}

impl CircuitBreakerSet {
    pub fn devnet() -> Self {
        Self {
            root: root_for("circuit-breakers", "wave105"),
            breakers: vec![
                CircuitBreaker::new("reorg-depth", CircuitBreakerStatus::Clear),
                CircuitBreaker::new("reserve-shortfall", CircuitBreakerStatus::Clear),
                CircuitBreaker::new("pq-quorum", CircuitBreakerStatus::Clear),
                CircuitBreaker::new("heavy-gate-live-feed", CircuitBreakerStatus::Clear),
                CircuitBreaker::new("credit-double-spend", CircuitBreakerStatus::Clear),
            ],
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_root("circuit_breaker_root", &self.root)?;
        if self.breakers.is_empty() {
            return Err(ReplayError::CircuitBreakerOpen(
                "at least one breaker status must be recorded".to_string(),
            ));
        }
        let mut ids = BTreeSet::new();
        for breaker in &self.breakers {
            breaker.validate()?;
            if !ids.insert(breaker.breaker_id.clone()) {
                return Err(ReplayError::CircuitBreakerOpen(format!(
                    "duplicate circuit breaker id {}",
                    breaker.breaker_id
                )));
            }
        }
        Ok(())
    }

    pub fn all_clear(&self) -> bool {
        self.breakers
            .iter()
            .all(|breaker| breaker.status == CircuitBreakerStatus::Clear)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitBreaker {
    pub breaker_id: String,
    pub status: CircuitBreakerStatus,
}

impl CircuitBreaker {
    pub fn new(breaker_id: &str, status: CircuitBreakerStatus) -> Self {
        Self {
            breaker_id: breaker_id.to_string(),
            status,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("breaker_id", &self.breaker_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CircuitBreakerStatus {
    Clear,
    Armed,
    Tripped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveHeavyGateEvidence {
    pub evidence_root: String,
    pub live_feed_root: String,
    pub claim_id: String,
    pub heavy_gates_ran: bool,
    pub observations: Vec<HeavyGateObservation>,
}

impl LiveHeavyGateEvidence {
    pub fn fail_closed() -> Self {
        Self {
            evidence_root: root_for("heavy-gate-empty", "fail-closed"),
            live_feed_root: root_for("live-feed-empty", "fail-closed"),
            claim_id: "fail-closed".to_string(),
            heavy_gates_ran: false,
            observations: Vec::new(),
        }
    }

    pub fn devnet(claim_id: &str) -> Self {
        Self {
            evidence_root: root_for("heavy-gate-evidence", claim_id),
            live_feed_root: root_for("live-heavy-gate-feed", claim_id),
            claim_id: claim_id.to_string(),
            heavy_gates_ran: true,
            observations: vec![
                HeavyGateObservation::new("relay-root-bound", true, 221_004),
                HeavyGateObservation::new("confirmation-root-bound", true, 221_008),
                HeavyGateObservation::new("reorg-root-bound", true, 221_010),
                HeavyGateObservation::new("credit-ledger-root-bound", true, 221_012),
            ],
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_root("evidence_root", &self.evidence_root)?;
        require_root("live_feed_root", &self.live_feed_root)?;
        require_non_empty("claim_id", &self.claim_id)?;
        for observation in &self.observations {
            observation.validate()?;
        }
        Ok(())
    }

    pub fn accepted_observations(&self) -> usize {
        self.observations
            .iter()
            .filter(|observation| observation.accepted)
            .count()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeavyGateObservation {
    pub gate_id: String,
    pub accepted: bool,
    pub observed_height: u64,
}

impl HeavyGateObservation {
    pub fn new(gate_id: &str, accepted: bool, observed_height: u64) -> Self {
        Self {
            gate_id: gate_id.to_string(),
            accepted,
            observed_height,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("gate_id", &self.gate_id)?;
        if self.observed_height == 0 {
            return Err(ReplayError::HeavyGateDenied(
                "heavy gate observation height must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignoffSet {
    pub signoff_root: String,
    pub signoffs: Vec<Signoff>,
}

impl SignoffSet {
    pub fn devnet() -> Self {
        Self {
            signoff_root: root_for("signoffs", "wave105"),
            signoffs: vec![
                Signoff::new("release-captain", "release", true),
                Signoff::new("bridge-custody", "reserve", true),
                Signoff::new("pq-authority", "pq", true),
                Signoff::new("risk-monitor", "reorg", true),
                Signoff::new("accounting", "credit", true),
                Signoff::new("heavy-gate-ops", "live-heavy-gate", true),
            ],
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_root("signoff_root", &self.signoff_root)?;
        if self.signoffs.is_empty() {
            return Err(ReplayError::SignoffDenied(
                "signoff set cannot be empty".to_string(),
            ));
        }
        let mut actors = BTreeSet::new();
        for signoff in &self.signoffs {
            signoff.validate()?;
            if !actors.insert(signoff.actor.clone()) {
                return Err(ReplayError::SignoffDenied(format!(
                    "duplicate signoff actor {}",
                    signoff.actor
                )));
            }
        }
        Ok(())
    }

    pub fn accepted_count(&self) -> usize {
        self.signoffs
            .iter()
            .filter(|signoff| signoff.approved)
            .count()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signoff {
    pub actor: String,
    pub domain: String,
    pub approved: bool,
}

impl Signoff {
    pub fn new(actor: &str, domain: &str, approved: bool) -> Self {
        Self {
            actor: actor.to_string(),
            domain: domain.to_string(),
            approved,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("actor", &self.actor)?;
        require_non_empty("domain", &self.domain)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayStep {
    pub step_index: u64,
    pub domain: ReplayDomain,
    pub input_root: String,
    pub output_root: String,
    pub accepted: bool,
}

impl ReplayStep {
    pub fn new(
        step_index: u64,
        domain: ReplayDomain,
        input_root: String,
        output_root: String,
        accepted: bool,
    ) -> Self {
        Self {
            step_index,
            domain,
            input_root,
            output_root,
            accepted,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_root("step_input_root", &self.input_root)?;
        require_root("step_output_root", &self.output_root)?;
        if self.step_index == 0 {
            return Err(ReplayError::ReplayDenied(
                "replay step index must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayDomain {
    Wave104RelayWitness,
    ConfirmationLadder,
    ReorgMonitor,
    CreditLedgerDelta,
    BeneficiaryAccounting,
    FeeRebateNetting,
    ReserveBalance,
    PqAuthorization,
    CircuitBreakers,
    LiveHeavyGateEvidence,
    SignoffQuorum,
}

impl fmt::Display for ReplayDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wave104RelayWitness => write!(f, "wave104-relay-witness"),
            Self::ConfirmationLadder => write!(f, "confirmation-ladder"),
            Self::ReorgMonitor => write!(f, "reorg-monitor"),
            Self::CreditLedgerDelta => write!(f, "credit-ledger-delta"),
            Self::BeneficiaryAccounting => write!(f, "beneficiary-accounting"),
            Self::FeeRebateNetting => write!(f, "fee-rebate-netting"),
            Self::ReserveBalance => write!(f, "reserve-balance"),
            Self::PqAuthorization => write!(f, "pq-authorization"),
            Self::CircuitBreakers => write!(f, "circuit-breakers"),
            Self::LiveHeavyGateEvidence => write!(f, "live-heavy-gate-evidence"),
            Self::SignoffQuorum => write!(f, "signoff-quorum"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayVerdict {
    pub release_credit_allowed: bool,
    pub credit_accounting_allowed: bool,
    pub heavy_gates_ran: bool,
    pub denied_reasons: Vec<String>,
    pub accepted_checks: Vec<String>,
    pub fail_closed_record: String,
}

impl ReplayVerdict {
    pub fn fail_closed(reason: &str) -> Self {
        Self {
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
            denied_reasons: vec![reason.to_string()],
            accepted_checks: Vec::new(),
            fail_closed_record: format!(
                "{}; {}; {}",
                FAIL_CLOSED_RELEASE, FAIL_CLOSED_ACCOUNTING, FAIL_CLOSED_HEAVY_GATE
            ),
        }
    }

    pub fn validate_fail_closed_text(&self) -> Result<()> {
        if !self.fail_closed_record.contains(FAIL_CLOSED_RELEASE) {
            return Err(ReplayError::InvalidEvidence(
                "fail closed record missing release_credit_allowed: false".to_string(),
            ));
        }
        if !self.fail_closed_record.contains(FAIL_CLOSED_ACCOUNTING) {
            return Err(ReplayError::InvalidEvidence(
                "fail closed record missing credit_accounting_allowed: false".to_string(),
            ));
        }
        if !self.fail_closed_record.contains(FAIL_CLOSED_HEAVY_GATE) {
            return Err(ReplayError::InvalidEvidence(
                "fail closed record missing heavy_gates_ran: false".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayPublicRecord {
    pub module_id: String,
    pub lane_id: String,
    pub sequence_id: String,
    pub state_root: String,
    pub release_credit_allowed: bool,
    pub credit_accounting_allowed: bool,
    pub heavy_gates_ran: bool,
    pub public_summary: String,
    pub fail_closed_defaults: String,
}

impl ReplayPublicRecord {
    pub fn fail_closed(reason: &str) -> Self {
        Self {
            module_id: MODULE_ID.to_string(),
            lane_id: MODULE_ID.to_string(),
            sequence_id: "fail-closed".to_string(),
            state_root: root_for("fail-closed-state", reason),
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
            public_summary: reason.to_string(),
            fail_closed_defaults: format!(
                "{}; {}; {}",
                FAIL_CLOSED_RELEASE, FAIL_CLOSED_ACCOUNTING, FAIL_CLOSED_HEAVY_GATE
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayError {
    InvalidConfig(String),
    InvalidEvidence(String),
    AccountingDenied(String),
    ReserveDenied(String),
    AuthorizationDenied(String),
    CircuitBreakerOpen(String),
    HeavyGateDenied(String),
    SignoffDenied(String),
    ReplayDenied(String),
    RootMismatch(String),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid config: {}", message),
            Self::InvalidEvidence(message) => write!(f, "invalid evidence: {}", message),
            Self::AccountingDenied(message) => write!(f, "accounting denied: {}", message),
            Self::ReserveDenied(message) => write!(f, "reserve denied: {}", message),
            Self::AuthorizationDenied(message) => write!(f, "authorization denied: {}", message),
            Self::CircuitBreakerOpen(message) => write!(f, "circuit breaker open: {}", message),
            Self::HeavyGateDenied(message) => write!(f, "heavy gate denied: {}", message),
            Self::SignoffDenied(message) => write!(f, "signoff denied: {}", message),
            Self::ReplayDenied(message) => write!(f, "replay denied: {}", message),
            Self::RootMismatch(message) => write!(f, "root mismatch: {}", message),
        }
    }
}

impl std::error::Error for ReplayError {}

pub fn devnet() -> Result<State> {
    State::new(Config::devnet(), ReplaySequence::devnet())
}

pub fn public_record(state: &State) -> PublicRecord {
    ReplayPublicRecord {
        module_id: MODULE_ID.to_string(),
        lane_id: state.config.lane_id.clone(),
        sequence_id: state.sequence.sequence_id.clone(),
        state_root: state_root(state),
        release_credit_allowed: state.verdict.release_credit_allowed,
        credit_accounting_allowed: state.verdict.credit_accounting_allowed,
        heavy_gates_ran: state.verdict.heavy_gates_ran,
        public_summary: summarize_public_record(state),
        fail_closed_defaults: state.verdict.fail_closed_record.clone(),
    }
}

pub fn state_root(state: &State) -> String {
    let mut parts = Vec::new();
    parts.push(MODULE_ID.to_string());
    parts.push(state.config.lane_id.clone());
    parts.push(state.config.wave_id.to_string());
    parts.push(state.sequence.sequence_id.clone());
    parts.push(state.sequence.wave104.binding_id.clone());
    parts.push(state.sequence.wave104.relay_witness_root.clone());
    parts.push(state.sequence.wave104.confirmation_ladder_root.clone());
    parts.push(state.sequence.wave104.reorg_monitor_root.clone());
    parts.push(state.sequence.relay_witness.root.clone());
    parts.push(state.sequence.confirmation_ladder.ladder_root.clone());
    parts.push(state.sequence.reorg_monitor.monitor_root.clone());
    parts.push(state.sequence.credit_ledger.ledger_root_before.clone());
    parts.push(state.sequence.credit_ledger.ledger_root_after.clone());
    parts.push(state.sequence.beneficiary.account_root_after.clone());
    parts.push(state.sequence.fee_rebate.netting_root.clone());
    parts.push(state.sequence.reserve.reserve_root.clone());
    parts.push(state.sequence.pq_authorization.authorization_root.clone());
    parts.push(state.sequence.circuit_breakers.root.clone());
    parts.push(state.sequence.live_heavy_gate.evidence_root.clone());
    parts.push(state.sequence.live_heavy_gate.live_feed_root.clone());
    parts.push(state.sequence.signoffs.signoff_root.clone());
    parts.push(state.verdict.release_credit_allowed.to_string());
    parts.push(state.verdict.credit_accounting_allowed.to_string());
    parts.push(state.verdict.heavy_gates_ran.to_string());
    digest_parts("state", &parts)
}

fn evaluate_sequence(config: &Config, sequence: &ReplaySequence) -> ReplayVerdict {
    let mut accepted = Vec::new();
    let mut denied = Vec::new();

    collect_result("config", config.validate(), &mut accepted, &mut denied);
    collect_result("sequence", sequence.validate(), &mut accepted, &mut denied);
    collect_bool(
        "wave104 relay root bound",
        sequence.wave104.relay_witness_root
            == root_for("wave104-relay", &sequence.credit_ledger.claim_id),
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "wave104 confirmation root bound",
        sequence.wave104.confirmation_ladder_root
            == root_for("wave104-confirmation", &sequence.credit_ledger.claim_id),
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "wave104 reorg root bound",
        sequence.wave104.reorg_monitor_root
            == root_for("wave104-reorg", &sequence.credit_ledger.claim_id),
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "confirmation depth floor met",
        sequence.confirmation_ladder.confirmed_depth >= config.min_confirmation_depth,
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "reorg monitor stable",
        sequence.reorg_monitor.competing_tip_count == 0
            && sequence.reorg_monitor.stable_window_observed,
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "credit ledger amount equals beneficiary credit",
        sequence.credit_ledger.credit_amount == sequence.beneficiary.observed_credit,
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "fee rebate netting bound",
        !config.require_fee_rebate_netting
            || sequence.fee_rebate.net_fee
                == sequence
                    .credit_ledger
                    .fee_amount
                    .saturating_sub(sequence.credit_ledger.rebate_amount),
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "beneficiary accounting bound",
        !config.require_beneficiary_match
            || sequence.beneficiary.planned_credit == sequence.beneficiary.observed_credit,
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "reserve balance sufficient",
        !config.require_reserve_balance
            || sequence.reserve.balance_after >= sequence.reserve.reserved_liabilities,
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "pq authorization accepted",
        !config.require_pq_authorization
            || sequence.pq_authorization.approvals >= sequence.pq_authorization.quorum,
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "circuit breakers clear",
        !config.require_circuit_breakers_clear || sequence.circuit_breakers.all_clear(),
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "live heavy gate evidence accepted",
        !config.require_live_feed
            || (sequence.live_heavy_gate.heavy_gates_ran
                && sequence.live_heavy_gate.accepted_observations()
                    >= config.min_heavy_gate_evidence),
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "signoff quorum accepted",
        sequence.signoffs.accepted_count() >= config.min_signoffs,
        &mut accepted,
        &mut denied,
    );
    collect_bool(
        "all replay steps accepted",
        sequence.replay_steps.iter().all(|step| step.accepted),
        &mut accepted,
        &mut denied,
    );

    if denied.is_empty() {
        ReplayVerdict {
            release_credit_allowed: true,
            credit_accounting_allowed: true,
            heavy_gates_ran: sequence.live_heavy_gate.heavy_gates_ran,
            denied_reasons: Vec::new(),
            accepted_checks: accepted,
            fail_closed_record: format!(
                "{}; {}; {}",
                FAIL_CLOSED_RELEASE, FAIL_CLOSED_ACCOUNTING, FAIL_CLOSED_HEAVY_GATE
            ),
        }
    } else {
        ReplayVerdict {
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
            denied_reasons: denied,
            accepted_checks: accepted,
            fail_closed_record: format!(
                "{}; {}; {}",
                FAIL_CLOSED_RELEASE, FAIL_CLOSED_ACCOUNTING, FAIL_CLOSED_HEAVY_GATE
            ),
        }
    }
}

fn validate_replay_steps(steps: &[ReplayStep]) -> Result<()> {
    if steps.len() < 11 {
        return Err(ReplayError::ReplayDenied(
            "replay lane must bind every required evidence domain".to_string(),
        ));
    }
    let mut planned_index = 1;
    let mut domains = BTreeSet::new();
    for step in steps {
        step.validate()?;
        if step.step_index != planned_index {
            return Err(ReplayError::ReplayDenied(
                "replay steps must be contiguous".to_string(),
            ));
        }
        domains.insert(step.domain.to_string());
        planned_index += 1;
    }
    let required = [
        ReplayDomain::Wave104RelayWitness,
        ReplayDomain::ConfirmationLadder,
        ReplayDomain::ReorgMonitor,
        ReplayDomain::CreditLedgerDelta,
        ReplayDomain::BeneficiaryAccounting,
        ReplayDomain::FeeRebateNetting,
        ReplayDomain::ReserveBalance,
        ReplayDomain::PqAuthorization,
        ReplayDomain::CircuitBreakers,
        ReplayDomain::LiveHeavyGateEvidence,
        ReplayDomain::SignoffQuorum,
    ];
    for domain in required {
        if !domains.contains(&domain.to_string()) {
            return Err(ReplayError::ReplayDenied(format!(
                "missing replay domain {}",
                domain
            )));
        }
    }
    Ok(())
}

fn devnet_replay_steps(claim_id: &str) -> Vec<ReplayStep> {
    let mut steps = Vec::new();
    let domains = [
        ReplayDomain::Wave104RelayWitness,
        ReplayDomain::ConfirmationLadder,
        ReplayDomain::ReorgMonitor,
        ReplayDomain::CreditLedgerDelta,
        ReplayDomain::BeneficiaryAccounting,
        ReplayDomain::FeeRebateNetting,
        ReplayDomain::ReserveBalance,
        ReplayDomain::PqAuthorization,
        ReplayDomain::CircuitBreakers,
        ReplayDomain::LiveHeavyGateEvidence,
        ReplayDomain::SignoffQuorum,
    ];
    let mut prior = root_for("replay-start", claim_id);
    let mut index = 1;
    for domain in domains {
        let label = format!("{}-{}", domain, index);
        let output = root_for("replay-step", &label);
        steps.push(ReplayStep::new(index, domain, prior, output.clone(), true));
        prior = output;
        index += 1;
    }
    steps
}

fn summarize_public_record(state: &State) -> String {
    format!(
        "{} sequence={} release={} accounting={} heavy_gate={} denied={}",
        MODULE_ID,
        state.sequence.sequence_id,
        state.verdict.release_credit_allowed,
        state.verdict.credit_accounting_allowed,
        state.verdict.heavy_gates_ran,
        state.verdict.denied_reasons.len()
    )
}

fn collect_result(
    label: &str,
    result: Result<()>,
    accepted: &mut Vec<String>,
    denied: &mut Vec<String>,
) {
    match result {
        Ok(()) => accepted.push(label.to_string()),
        Err(error) => denied.push(format!("{}: {}", label, error)),
    }
}

fn collect_bool(label: &str, passed: bool, accepted: &mut Vec<String>, denied: &mut Vec<String>) {
    if passed {
        accepted.push(label.to_string());
    } else {
        denied.push(label.to_string());
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(ReplayError::InvalidEvidence(format!(
            "{} must not be empty",
            field
        )));
    }
    Ok(())
}

fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if !value.starts_with(ROOT_PREFIX) {
        return Err(ReplayError::InvalidEvidence(format!(
            "{} root must use wave105 prefix",
            field
        )));
    }
    Ok(())
}

fn validate_strictly_increasing(field: &str, values: &[u64]) -> Result<()> {
    let mut previous = 0;
    for value in values {
        if *value <= previous {
            return Err(ReplayError::InvalidEvidence(format!(
                "{} must be strictly increasing",
                field
            )));
        }
        previous = *value;
    }
    Ok(())
}

fn root_for(domain: &str, label: &str) -> String {
    digest_parts(domain, &[domain.to_string(), label.to_string()])
}

fn digest_parts(domain: &str, parts: &[String]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in domain.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
            hash ^= hash.rotate_left(13);
        }
    }
    format!("{}-{}-{:016x}", ROOT_PREFIX, domain.replace('_', "-"), hash)
}
