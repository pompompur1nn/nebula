use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

const CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
const PROTOCOL_VERSION: &str =
    "wave105-live-heavy-gate-release-execution-monero-tx-confirmed-credit-accounting-guard-final-transcript-runtime-v1";
const WAVE: u64 = 105;
const RELAY_CONFIRMATION_WAVE: u64 = 104;
const MIN_RELAY_CONFIRMATION_HEIGHT: u64 = 1_050_000;
const MIN_CONFIRMATION_LADDER_DEPTH: u64 = 32;
const MIN_REORG_MONITOR_DEPTH: u64 = 40;
const MAX_CREDIT_FEE_BPS: u64 = 8;
const LANE_ID: &str =
    "wave105-live-heavy-gate-release-execution-monero-tx-confirmed-credit-accounting-guard-final-transcript";

pub type PublicRecord = Value;
pub type Runtime = State;
pub type Result<T> = core::result::Result<T, CreditAccountingError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CreditAccountingError {
    LaneMissing,
    ClaimMissing,
    Wave104RelayConfirmationRootMissing,
    CreditLedgerDeltaRootMissing,
    RelayWitnessRootMissing,
    BeneficiaryAccountingRootMissing,
    FeeRebateNettingRootMissing,
    ReserveBalanceRootMissing,
    ConfirmationLadderRootMissing,
    ReorgMonitorRootMissing,
    PqAuthorizationRootMissing,
    CircuitBreakerRootMissing,
    OperatorSignoffRootMissing,
    ReviewerSignoffRootMissing,
    LiveHeavyGateEvidenceRootMissing,
    RelayConfirmationHeightTooLow,
    ConfirmationLadderTooShallow,
    ReorgMonitorTooShallow,
    CreditFeeTooHigh,
    ReleaseCreditStillDenied,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LaneKind {
    Compile,
    RuntimeReplay,
    AuditSecurity,
    BridgeCustody,
    WalletWatchtower,
    PqReservePrivacy,
    FinalTranscript,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::RuntimeReplay => "runtime_replay",
            Self::AuditSecurity => "audit_security",
            Self::BridgeCustody => "bridge_custody",
            Self::WalletWatchtower => "wallet_watchtower",
            Self::PqReservePrivacy => "pq_reserve_privacy",
            Self::FinalTranscript => "final_transcript",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Compile => "Compile Monero tx confirmed credit accounting guard",
            Self::RuntimeReplay => "Runtime replay Monero tx confirmed credit accounting guard",
            Self::AuditSecurity => "Audit security Monero tx confirmed credit accounting guard",
            Self::BridgeCustody => "Bridge custody Monero tx confirmed credit accounting guard",
            Self::WalletWatchtower => {
                "Wallet watchtower Monero tx confirmed credit accounting guard"
            }
            Self::PqReservePrivacy => {
                "PQ reserve privacy Monero tx confirmed credit accounting guard"
            }
            Self::FinalTranscript => "Final transcript Monero tx confirmed credit accounting guard",
        }
    }

    pub fn command_scope(self) -> &'static str {
        match self {
            Self::Compile => "compile-monero-relay-confirmation",
            Self::RuntimeReplay => "runtime-replay-monero-relay-confirmation",
            Self::AuditSecurity => "audit-security-monero-relay-confirmation",
            Self::BridgeCustody => "bridge-custody-monero-relay-confirmation",
            Self::WalletWatchtower => "wallet-watchtower-monero-relay-confirmation",
            Self::PqReservePrivacy => "pq-reserve-privacy-monero-relay-confirmation",
            Self::FinalTranscript => "final-transcript-monero-relay-confirmation",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CreditAccountingStatus {
    Empty,
    Blocked,
    CreditLedgerCandidate,
    BeneficiaryAccounted,
    ReserveBalanced,
    CreditAccountingReady,
}

impl CreditAccountingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Blocked => "blocked",
            Self::CreditLedgerCandidate => "credit_ledger_candidate",
            Self::BeneficiaryAccounted => "beneficiary_accounted",
            Self::ReserveBalanced => "reserve_balanced",
            Self::CreditAccountingReady => "credit_accounting_ready",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CreditAccountingBlockerKind {
    MissingWave104RelayConfirmationRoot,
    MissingCreditLedgerDeltaRoot,
    MissingRelayWitnessRoot,
    MissingBeneficiaryAccountingRoot,
    MissingFeeRebateNettingRoot,
    MissingReserveBalanceRoot,
    MissingConfirmationLadderRoot,
    MissingReorgMonitorRoot,
    MissingPqAuthorizationRoot,
    MissingCircuitBreakerRoot,
    MissingOperatorSignoffRoot,
    MissingReviewerSignoffRoot,
    MissingLiveHeavyGateEvidenceRoot,
    RelayConfirmationHeightTooLow,
    ConfirmationLadderTooShallow,
    ReorgMonitorTooShallow,
    CreditFeeTooHigh,
    CircuitBreakerArmed,
    ReleaseCreditDenied,
    RootsOnlyBoundary,
}

impl CreditAccountingBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingWave104RelayConfirmationRoot => "missing_wave104_relay_confirmation_root",
            Self::MissingCreditLedgerDeltaRoot => "missing_credit_ledger_delta_root",
            Self::MissingRelayWitnessRoot => "missing_relay_witness_root",
            Self::MissingBeneficiaryAccountingRoot => "missing_beneficiary_accounting_root",
            Self::MissingFeeRebateNettingRoot => "missing_fee_rebate_netting_root",
            Self::MissingReserveBalanceRoot => "missing_reserve_balance_root",
            Self::MissingConfirmationLadderRoot => "missing_confirmation_ladder_root",
            Self::MissingReorgMonitorRoot => "missing_reorg_monitor_root",
            Self::MissingPqAuthorizationRoot => "missing_pq_authorization_root",
            Self::MissingCircuitBreakerRoot => "missing_circuit_breaker_root",
            Self::MissingOperatorSignoffRoot => "missing_operator_signoff_root",
            Self::MissingReviewerSignoffRoot => "missing_reviewer_signoff_root",
            Self::MissingLiveHeavyGateEvidenceRoot => "missing_live_heavy_gate_evidence_root",
            Self::RelayConfirmationHeightTooLow => "relay_confirmation_height_too_low",
            Self::ConfirmationLadderTooShallow => "confirmation_ladder_too_shallow",
            Self::ReorgMonitorTooShallow => "reorg_monitor_too_shallow",
            Self::CreditFeeTooHigh => "credit_fee_too_high",
            Self::CircuitBreakerArmed => "circuit_breaker_armed",
            Self::ReleaseCreditDenied => "release_credit_denied",
            Self::RootsOnlyBoundary => "roots_only_boundary",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub wave: u64,
    pub relay_confirmation_wave: u64,
    pub lane_id: String,
    pub min_relay_confirmation_height: u64,
    pub min_confirmation_ladder_depth: u64,
    pub min_reorg_monitor_depth: u64,
    pub max_credit_fee_bps: u64,
    pub require_wave104_relay_confirmation_root: bool,
    pub require_credit_ledger_delta_root: bool,
    pub require_relay_witness_root: bool,
    pub require_beneficiary_accounting_root: bool,
    pub require_fee_rebate_netting_root: bool,
    pub require_reserve_balance_root: bool,
    pub require_confirmation_ladder_root: bool,
    pub require_reorg_monitor_root: bool,
    pub require_pq_authorization_root: bool,
    pub require_circuit_breaker_root: bool,
    pub require_operator_signoff_root: bool,
    pub require_reviewer_signoff_root: bool,
    pub require_live_heavy_gate_evidence: bool,
    pub arm_circuit_breaker_by_default: bool,
    pub credit_accounting_allowed: bool,
    pub release_credit_allowed: bool,
    pub heavy_gates_ran: bool,
    pub roots_only_public_records: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            wave: WAVE,
            relay_confirmation_wave: RELAY_CONFIRMATION_WAVE,
            lane_id: LANE_ID.to_string(),
            min_relay_confirmation_height: MIN_RELAY_CONFIRMATION_HEIGHT,
            min_confirmation_ladder_depth: MIN_CONFIRMATION_LADDER_DEPTH,
            min_reorg_monitor_depth: MIN_REORG_MONITOR_DEPTH,
            max_credit_fee_bps: MAX_CREDIT_FEE_BPS,
            require_wave104_relay_confirmation_root: true,
            require_credit_ledger_delta_root: true,
            require_relay_witness_root: true,
            require_beneficiary_accounting_root: true,
            require_fee_rebate_netting_root: true,
            require_reserve_balance_root: true,
            require_confirmation_ladder_root: true,
            require_reorg_monitor_root: true,
            require_pq_authorization_root: true,
            require_circuit_breaker_root: true,
            require_operator_signoff_root: true,
            require_reviewer_signoff_root: true,
            require_live_heavy_gate_evidence: true,
            arm_circuit_breaker_by_default: true,
            credit_accounting_allowed: false,
            release_credit_allowed: false,
            heavy_gates_ran: false,
            roots_only_public_records: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> PublicRecord {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "wave": self.wave,
            "relay_confirmation_wave": self.relay_confirmation_wave,
            "lane_id": self.lane_id,
            "min_relay_confirmation_height": self.min_relay_confirmation_height,
            "min_confirmation_ladder_depth": self.min_confirmation_ladder_depth,
            "min_reorg_monitor_depth": self.min_reorg_monitor_depth,
            "max_credit_fee_bps": self.max_credit_fee_bps,
            "require_wave104_relay_confirmation_root": self.require_wave104_relay_confirmation_root,
            "require_credit_ledger_delta_root": self.require_credit_ledger_delta_root,
            "require_relay_witness_root": self.require_relay_witness_root,
            "require_beneficiary_accounting_root": self.require_beneficiary_accounting_root,
            "require_fee_rebate_netting_root": self.require_fee_rebate_netting_root,
            "require_reserve_balance_root": self.require_reserve_balance_root,
            "require_confirmation_ladder_root": self.require_confirmation_ladder_root,
            "require_reorg_monitor_root": self.require_reorg_monitor_root,
            "require_pq_authorization_root": self.require_pq_authorization_root,
            "require_circuit_breaker_root": self.require_circuit_breaker_root,
            "require_operator_signoff_root": self.require_operator_signoff_root,
            "require_reviewer_signoff_root": self.require_reviewer_signoff_root,
            "require_live_heavy_gate_evidence": self.require_live_heavy_gate_evidence,
            "arm_circuit_breaker_by_default": self.arm_circuit_breaker_by_default,
            "credit_accounting_allowed": self.credit_accounting_allowed,
            "release_credit_allowed": self.release_credit_allowed,
            "heavy_gates_ran": self.heavy_gates_ran,
            "roots_only_public_records": self.roots_only_public_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CreditAccountingRoots {
    pub wave104_relay_confirmation_root: Option<String>,
    pub credit_ledger_delta_root: Option<String>,
    pub relay_witness_root: Option<String>,
    pub beneficiary_accounting_root: Option<String>,
    pub fee_rebate_netting_root: Option<String>,
    pub reserve_balance_root: Option<String>,
    pub confirmation_ladder_root: Option<String>,
    pub reorg_monitor_root: Option<String>,
    pub pq_authorization_root: Option<String>,
    pub circuit_breaker_root: Option<String>,
    pub operator_signoff_root: Option<String>,
    pub reviewer_signoff_root: Option<String>,
    pub live_heavy_gate_evidence_root: Option<String>,
}

impl CreditAccountingRoots {
    pub fn public_record(&self) -> PublicRecord {
        json!({
            "wave104_relay_confirmation_root": self.wave104_relay_confirmation_root,
            "credit_ledger_delta_root": self.credit_ledger_delta_root,
            "relay_witness_root": self.relay_witness_root,
            "beneficiary_accounting_root": self.beneficiary_accounting_root,
            "fee_rebate_netting_root": self.fee_rebate_netting_root,
            "reserve_balance_root": self.reserve_balance_root,
            "confirmation_ladder_root": self.confirmation_ladder_root,
            "reorg_monitor_root": self.reorg_monitor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "operator_signoff_root": self.operator_signoff_root,
            "reviewer_signoff_root": self.reviewer_signoff_root,
            "live_heavy_gate_evidence_root": self.live_heavy_gate_evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("credit_accounting_roots", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct CreditAccountingMeasurements {
    pub relay_witness_height: u64,
    pub confirmation_ladder_depth: u64,
    pub reorg_monitor_depth: u64,
    pub credit_fee_bps: u64,
}

impl CreditAccountingMeasurements {
    pub fn blocked(config: &Config) -> Self {
        Self {
            relay_witness_height: config.min_relay_confirmation_height.saturating_sub(1),
            confirmation_ladder_depth: config.min_confirmation_ladder_depth.saturating_sub(1),
            reorg_monitor_depth: config.min_reorg_monitor_depth.saturating_sub(1),
            credit_fee_bps: config.max_credit_fee_bps.saturating_add(1),
        }
    }

    pub fn public_record(self) -> PublicRecord {
        json!({
            "relay_witness_height": self.relay_witness_height,
            "confirmation_ladder_depth": self.confirmation_ladder_depth,
            "reorg_monitor_depth": self.reorg_monitor_depth,
            "credit_fee_bps": self.credit_fee_bps,
        })
    }

    pub fn state_root(self) -> String {
        record_root("credit_accounting_measurements", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreditAccountingPolicy {
    pub lane: LaneKind,
    pub claim_label: String,
    pub ordinal: u64,
    pub command_scope: String,
    pub command_hint: String,
    pub relay_policy_root: String,
    pub mempool_policy_root: String,
    pub confirmation_policy_root: String,
    pub reorg_policy_root: String,
    pub credit_policy_root: String,
}

impl CreditAccountingPolicy {
    pub fn new(lane: LaneKind, claim_label: &str, ordinal: u64) -> Self {
        let command_scope = lane.command_scope().to_string();
        let command_hint = format!(
            "nebula wave105 confirm-relay --lane {} --claim {} --hold-credit",
            lane.as_str(),
            claim_label
        );
        Self {
            lane,
            claim_label: claim_label.to_string(),
            ordinal,
            command_scope,
            command_hint,
            relay_policy_root: label_root("relay_policy", lane.as_str(), claim_label, ordinal),
            mempool_policy_root: label_root("mempool_policy", lane.as_str(), claim_label, ordinal),
            confirmation_policy_root: label_root(
                "confirmation_policy",
                lane.as_str(),
                claim_label,
                ordinal,
            ),
            reorg_policy_root: label_root("reorg_policy", lane.as_str(), claim_label, ordinal),
            credit_policy_root: label_root("credit_policy", lane.as_str(), claim_label, ordinal),
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "lane": self.lane.as_str(),
            "claim_label": self.claim_label,
            "ordinal": self.ordinal,
            "command_scope": self.command_scope,
            "command_hint": self.command_hint,
            "relay_policy_root": self.relay_policy_root,
            "mempool_policy_root": self.mempool_policy_root,
            "confirmation_policy_root": self.confirmation_policy_root,
            "reorg_policy_root": self.reorg_policy_root,
            "credit_policy_root": self.credit_policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("credit_accounting_policy", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreditAccountingCheckpoint {
    pub lane: LaneKind,
    pub claim_label: String,
    pub ordinal: u64,
    pub roots: CreditAccountingRoots,
    pub measurements: CreditAccountingMeasurements,
    pub policy: CreditAccountingPolicy,
    pub status: CreditAccountingStatus,
    pub blockers: Vec<CreditAccountingBlockerKind>,
    pub credit_accounting_allowed: bool,
    pub release_credit_allowed: bool,
}

impl CreditAccountingCheckpoint {
    pub fn empty(lane: LaneKind, claim_label: &str, ordinal: u64, config: &Config) -> Self {
        let policy = CreditAccountingPolicy::new(lane, claim_label, ordinal);
        Self {
            lane,
            claim_label: claim_label.to_string(),
            ordinal,
            roots: CreditAccountingRoots::default(),
            measurements: CreditAccountingMeasurements::blocked(config),
            policy,
            status: CreditAccountingStatus::Blocked,
            blockers: initial_blockers(config),
            credit_accounting_allowed: false,
            release_credit_allowed: false,
        }
    }

    pub fn stage_confirmation(
        mut self,
        roots: CreditAccountingRoots,
        measurements: CreditAccountingMeasurements,
        config: &Config,
    ) -> Self {
        self.roots = roots;
        self.measurements = measurements;
        self.blockers = self.active_blockers(config);
        self.status = if self.blockers.is_empty() {
            CreditAccountingStatus::ReserveBalanced
        } else if self.roots.reserve_balance_root.is_some() {
            CreditAccountingStatus::ReserveBalanced
        } else if self.roots.beneficiary_accounting_root.is_some() {
            CreditAccountingStatus::BeneficiaryAccounted
        } else if self.roots.relay_witness_root.is_some() {
            CreditAccountingStatus::CreditLedgerCandidate
        } else {
            CreditAccountingStatus::Blocked
        };
        self.credit_accounting_allowed = false;
        self.release_credit_allowed = false;
        self
    }

    pub fn release_credit(mut self, config: &Config) -> Result<Self> {
        self.blockers = self.active_blockers(config);
        if self.blockers.is_empty() {
            self.status = CreditAccountingStatus::CreditAccountingReady;
            self.credit_accounting_allowed = true;
            self.release_credit_allowed = true;
            Ok(self)
        } else {
            Err(CreditAccountingError::ReleaseCreditStillDenied)
        }
    }

    pub fn active_blockers(&self, config: &Config) -> Vec<CreditAccountingBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_wave104_relay_confirmation_root
            && self.roots.wave104_relay_confirmation_root.is_none()
        {
            blockers.push(CreditAccountingBlockerKind::MissingWave104RelayConfirmationRoot);
        }
        if config.require_credit_ledger_delta_root && self.roots.credit_ledger_delta_root.is_none()
        {
            blockers.push(CreditAccountingBlockerKind::MissingCreditLedgerDeltaRoot);
        }
        if config.require_relay_witness_root && self.roots.relay_witness_root.is_none() {
            blockers.push(CreditAccountingBlockerKind::MissingRelayWitnessRoot);
        }
        if config.require_beneficiary_accounting_root
            && self.roots.beneficiary_accounting_root.is_none()
        {
            blockers.push(CreditAccountingBlockerKind::MissingBeneficiaryAccountingRoot);
        }
        if config.require_fee_rebate_netting_root && self.roots.fee_rebate_netting_root.is_none() {
            blockers.push(CreditAccountingBlockerKind::MissingFeeRebateNettingRoot);
        }
        if config.require_reserve_balance_root && self.roots.reserve_balance_root.is_none() {
            blockers.push(CreditAccountingBlockerKind::MissingReserveBalanceRoot);
        }
        if config.require_confirmation_ladder_root && self.roots.confirmation_ladder_root.is_none()
        {
            blockers.push(CreditAccountingBlockerKind::MissingConfirmationLadderRoot);
        }
        if config.require_reorg_monitor_root && self.roots.reorg_monitor_root.is_none() {
            blockers.push(CreditAccountingBlockerKind::MissingReorgMonitorRoot);
        }
        if config.require_pq_authorization_root && self.roots.pq_authorization_root.is_none() {
            blockers.push(CreditAccountingBlockerKind::MissingPqAuthorizationRoot);
        }
        if config.require_circuit_breaker_root && self.roots.circuit_breaker_root.is_none() {
            blockers.push(CreditAccountingBlockerKind::MissingCircuitBreakerRoot);
        }
        if config.require_operator_signoff_root && self.roots.operator_signoff_root.is_none() {
            blockers.push(CreditAccountingBlockerKind::MissingOperatorSignoffRoot);
        }
        if config.require_reviewer_signoff_root && self.roots.reviewer_signoff_root.is_none() {
            blockers.push(CreditAccountingBlockerKind::MissingReviewerSignoffRoot);
        }
        if config.require_live_heavy_gate_evidence
            && self.roots.live_heavy_gate_evidence_root.is_none()
        {
            blockers.push(CreditAccountingBlockerKind::MissingLiveHeavyGateEvidenceRoot);
        }
        if self.measurements.relay_witness_height < config.min_relay_confirmation_height {
            blockers.push(CreditAccountingBlockerKind::RelayConfirmationHeightTooLow);
        }
        if self.measurements.confirmation_ladder_depth < config.min_confirmation_ladder_depth {
            blockers.push(CreditAccountingBlockerKind::ConfirmationLadderTooShallow);
        }
        if self.measurements.reorg_monitor_depth < config.min_reorg_monitor_depth {
            blockers.push(CreditAccountingBlockerKind::ReorgMonitorTooShallow);
        }
        if self.measurements.credit_fee_bps > config.max_credit_fee_bps {
            blockers.push(CreditAccountingBlockerKind::CreditFeeTooHigh);
        }
        if config.arm_circuit_breaker_by_default {
            blockers.push(CreditAccountingBlockerKind::CircuitBreakerArmed);
        }
        if !config.credit_accounting_allowed || !config.release_credit_allowed {
            blockers.push(CreditAccountingBlockerKind::ReleaseCreditDenied);
        }
        if config.roots_only_public_records {
            blockers.push(CreditAccountingBlockerKind::RootsOnlyBoundary);
        }
        blockers
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "lane": self.lane.as_str(),
            "lane_title": self.lane.title(),
            "claim_label": self.claim_label,
            "ordinal": self.ordinal,
            "roots_root": self.roots.state_root(),
            "measurements_root": self.measurements.state_root(),
            "policy_root": self.policy.state_root(),
            "status": self.status.as_str(),
            "blockers": self.blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
            "credit_accounting_allowed": self.credit_accounting_allowed,
            "release_credit_allowed": self.release_credit_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("credit_accounting_checkpoint", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub lane: LaneKind,
    pub lane_title: String,
    pub checkpoints: Vec<CreditAccountingCheckpoint>,
    pub command_hints: Vec<String>,
    pub credit_accounting_allowed: bool,
    pub release_credit_allowed: bool,
    pub heavy_gates_ran: bool,
}

impl State {
    pub fn new(
        config: Config,
        lane: LaneKind,
        checkpoints: Vec<CreditAccountingCheckpoint>,
    ) -> Self {
        let command_hints = checkpoints
            .iter()
            .map(|checkpoint| checkpoint.policy.command_hint.clone())
            .collect::<Vec<_>>();
        Self {
            config,
            lane,
            lane_title: lane.title().to_string(),
            checkpoints,
            command_hints,
            credit_accounting_allowed: false,
            release_credit_allowed: false,
            heavy_gates_ran: false,
        }
    }

    pub fn active_blockers(&self) -> Vec<CreditAccountingBlockerKind> {
        self.checkpoints
            .iter()
            .flat_map(|checkpoint| checkpoint.blockers.iter().copied())
            .collect::<Vec<_>>()
    }

    pub fn ready_count(&self) -> usize {
        self.checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.status == CreditAccountingStatus::CreditAccountingReady)
            .count()
    }

    pub fn blocked_count(&self) -> usize {
        self.checkpoints
            .iter()
            .filter(|checkpoint| !checkpoint.blockers.is_empty())
            .count()
    }

    pub fn relay_witness_root(&self) -> String {
        status_root(
            "wave105_monero_tx_credit_ledger_candidates",
            &self.checkpoints,
            CreditAccountingStatus::CreditLedgerCandidate,
        )
    }

    pub fn beneficiary_accounting_root(&self) -> String {
        status_root(
            "wave105_monero_tx_mempool_acceptance_candidates",
            &self.checkpoints,
            CreditAccountingStatus::BeneficiaryAccounted,
        )
    }

    pub fn reserve_balanced_root(&self) -> String {
        status_root(
            "wave105_monero_tx_reserve_balanceds",
            &self.checkpoints,
            CreditAccountingStatus::ReserveBalanced,
        )
    }

    pub fn credit_accounting_ready_root(&self) -> String {
        status_root(
            "wave105_monero_tx_credit_accounting_ready",
            &self.checkpoints,
            CreditAccountingStatus::CreditAccountingReady,
        )
    }

    pub fn blocked_root(&self) -> String {
        blocked_root(&self.checkpoints)
    }

    pub fn command_root(&self) -> String {
        root_from_strings(
            "wave105_monero_tx_credit_accounting_command_hints",
            self.command_hints.clone(),
        )
    }

    pub fn lane_summary_root(&self) -> String {
        domain_hash(
            "wave105-monero-tx-confirmed-credit-accounting-lane-summary",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(LANE_ID),
                HashPart::Str(self.lane.as_str()),
                HashPart::U64(WAVE),
                HashPart::U64(self.checkpoints.len() as u64),
                HashPart::U64(self.blocked_count() as u64),
                HashPart::U64(self.ready_count() as u64),
            ],
            32,
        )
    }

    pub fn release_credit_denial_root(&self) -> String {
        let blocker_labels = self
            .active_blockers()
            .into_iter()
            .map(|blocker| blocker.as_str().to_string())
            .collect::<Vec<_>>();
        root_from_strings(
            "wave105_monero_tx_release_credit_denial_blockers",
            blocker_labels,
        )
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "config_root": self.config.state_root(),
            "lane": self.lane.as_str(),
            "lane_title": self.lane_title,
            "checkpoint_count": self.checkpoints.len(),
            "blocked_count": self.blocked_count(),
            "ready_count": self.ready_count(),
            "relay_witness_root": self.relay_witness_root(),
            "beneficiary_accounting_root": self.beneficiary_accounting_root(),
            "reserve_balanced_root": self.reserve_balanced_root(),
            "credit_accounting_ready_root": self.credit_accounting_ready_root(),
            "blocked_root": self.blocked_root(),
            "command_root": self.command_root(),
            "lane_summary_root": self.lane_summary_root(),
            "release_credit_denial_root": self.release_credit_denial_root(),
            "credit_accounting_allowed": self.credit_accounting_allowed,
            "release_credit_allowed": self.release_credit_allowed,
            "heavy_gates_ran": self.heavy_gates_ran,
            "checkpoints": self.checkpoints.iter().map(|checkpoint| checkpoint.public_record()).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }
}

pub fn devnet() -> State {
    let config = Config::default();
    let lane = LaneKind::FinalTranscript;
    let claim_labels = [
        "compile_lane_credit_accounting",
        "runtime_lane_credit_accounting",
        "audit_lane_credit_accounting",
        "custody_lane_credit_accounting",
        "wallet_lane_credit_accounting",
        "pq_privacy_lane_credit_accounting",
        "global_release_credit_hold",
    ];
    let checkpoints = claim_labels
        .iter()
        .enumerate()
        .map(|(index, claim_label)| {
            CreditAccountingCheckpoint::empty(lane, claim_label, (index + 1) as u64, &config)
        })
        .collect::<Vec<_>>();
    State::new(config, lane, checkpoints)
}

pub fn public_record() -> PublicRecord {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn initial_blockers(config: &Config) -> Vec<CreditAccountingBlockerKind> {
    let mut blockers = Vec::new();
    if config.require_wave104_relay_confirmation_root {
        blockers.push(CreditAccountingBlockerKind::MissingWave104RelayConfirmationRoot);
    }
    if config.require_credit_ledger_delta_root {
        blockers.push(CreditAccountingBlockerKind::MissingCreditLedgerDeltaRoot);
    }
    if config.require_relay_witness_root {
        blockers.push(CreditAccountingBlockerKind::MissingRelayWitnessRoot);
    }
    if config.require_beneficiary_accounting_root {
        blockers.push(CreditAccountingBlockerKind::MissingBeneficiaryAccountingRoot);
    }
    if config.require_fee_rebate_netting_root {
        blockers.push(CreditAccountingBlockerKind::MissingFeeRebateNettingRoot);
    }
    if config.require_reserve_balance_root {
        blockers.push(CreditAccountingBlockerKind::MissingReserveBalanceRoot);
    }
    if config.require_confirmation_ladder_root {
        blockers.push(CreditAccountingBlockerKind::MissingConfirmationLadderRoot);
    }
    if config.require_reorg_monitor_root {
        blockers.push(CreditAccountingBlockerKind::MissingReorgMonitorRoot);
    }
    if config.require_pq_authorization_root {
        blockers.push(CreditAccountingBlockerKind::MissingPqAuthorizationRoot);
    }
    if config.require_circuit_breaker_root {
        blockers.push(CreditAccountingBlockerKind::MissingCircuitBreakerRoot);
    }
    if config.require_operator_signoff_root {
        blockers.push(CreditAccountingBlockerKind::MissingOperatorSignoffRoot);
    }
    if config.require_reviewer_signoff_root {
        blockers.push(CreditAccountingBlockerKind::MissingReviewerSignoffRoot);
    }
    if config.require_live_heavy_gate_evidence {
        blockers.push(CreditAccountingBlockerKind::MissingLiveHeavyGateEvidenceRoot);
    }
    blockers.push(CreditAccountingBlockerKind::RelayConfirmationHeightTooLow);
    blockers.push(CreditAccountingBlockerKind::ConfirmationLadderTooShallow);
    blockers.push(CreditAccountingBlockerKind::ReorgMonitorTooShallow);
    blockers.push(CreditAccountingBlockerKind::CreditFeeTooHigh);
    if config.arm_circuit_breaker_by_default {
        blockers.push(CreditAccountingBlockerKind::CircuitBreakerArmed);
    }
    if !config.credit_accounting_allowed || !config.release_credit_allowed {
        blockers.push(CreditAccountingBlockerKind::ReleaseCreditDenied);
    }
    if config.roots_only_public_records {
        blockers.push(CreditAccountingBlockerKind::RootsOnlyBoundary);
    }
    blockers
}

fn blocked_root(checkpoints: &[CreditAccountingCheckpoint]) -> String {
    let leaves = checkpoints
        .iter()
        .flat_map(|checkpoint| {
            checkpoint.blockers.iter().map(move |blocker| {
                json!({
                    "lane": checkpoint.lane.as_str(),
                    "claim_label": checkpoint.claim_label,
                    "blocker": blocker.as_str(),
                    "checkpoint_root": checkpoint.state_root(),
                })
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "wave105_blocked_monero_tx_credit_accounting_guards",
        &leaves,
    )
}

fn status_root(
    domain: &str,
    checkpoints: &[CreditAccountingCheckpoint],
    status: CreditAccountingStatus,
) -> String {
    root_from_strings(
        domain,
        checkpoints.iter().filter_map(|checkpoint| {
            if checkpoint.status == status {
                Some(checkpoint.state_root())
            } else {
                None
            }
        }),
    )
}

fn root_from_strings<I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = values.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "wave105-live-heavy-gate-release-execution-monero-tx-relay-confirmation-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn label_root(kind: &str, lane: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "wave105-live-heavy-gate-release-execution-monero-tx-relay-confirmation-label",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(lane),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn devnet_credit_accounting_root() -> String {
    let state = devnet();
    domain_hash(
        "wave105-live-heavy-gate-release-execution-monero-tx-relay-confirmation-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(LANE_ID),
            HashPart::Str(&state.blocked_root()),
            HashPart::Str(&state.release_credit_denial_root()),
        ],
        32,
    )
}
