use std::collections::BTreeSet;

pub type PublicRecord = String;
pub type Runtime = State;
pub type Result<T> = std::result::Result<T, RuntimeError>;

const CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
const PROTOCOL_VERSION: &str =
    "wave105-live-heavy-gate-release-execution-monero-confirmed-credit-accounting-guard-pq-reserve-privacy-lane-runtime-v1";
const LANE_ID: &str = "monero-confirmed-credit-accounting-guard-pq-reserve-privacy-lane";
const WAVE: u64 = 105;
const PREVIOUS_CONFIRMATION_WAVE: u64 = 104;
const MIN_PQ_AUTHORITY_COUNT: u64 = 5;
const MIN_PQ_QUORUM_BPS: u64 = 7_000;
const MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
const MIN_RESERVE_PROOF_DEPTH: u64 = 720;
const MIN_AMOUNT_BUCKET_SIZE: u64 = 32;
const MIN_BENEFICIARY_COMMITMENTS: u64 = 16;
const MIN_RELAY_CONFIRMATION_DEPTH: u64 = 10;
const MIN_RELAY_CONFIRMATION_ROOTS: u64 = 3;
const MIN_REORG_SAFETY_DEPTH: u64 = 720;
const MAX_REORG_RISK_BPS: u64 = 5;
const MAX_FEE_REBATE_DRIFT_PICONERO: i128 = 0;
const MIN_HEAVY_GATE_EVIDENCE_COUNT: u64 = 12;
const MIN_SIGNOFF_COUNT: u64 = 3;
const MAX_RECORDS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeError {
    DuplicateRecordRoot,
    RecordLimitExceeded,
    EmptyRecordRoot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GateKind {
    PqAuthorizationRoots,
    ReserveBalanceProofs,
    AmountBucketPrivacy,
    BeneficiaryCommitments,
    RelayConfirmationRoots,
    ReorgSafety,
    FeeRebateNetting,
    CircuitBreakers,
    LiveHeavyGateEvidence,
    OperatorSignoff,
    ReviewerSignoff,
    ReleaseCreditAccounting,
}

impl GateKind {
    pub fn all() -> [Self; 12] {
        [
            Self::PqAuthorizationRoots,
            Self::ReserveBalanceProofs,
            Self::AmountBucketPrivacy,
            Self::BeneficiaryCommitments,
            Self::RelayConfirmationRoots,
            Self::ReorgSafety,
            Self::FeeRebateNetting,
            Self::CircuitBreakers,
            Self::LiveHeavyGateEvidence,
            Self::OperatorSignoff,
            Self::ReviewerSignoff,
            Self::ReleaseCreditAccounting,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqAuthorizationRoots => "pq_authorization_roots",
            Self::ReserveBalanceProofs => "reserve_balance_proofs",
            Self::AmountBucketPrivacy => "amount_bucket_privacy",
            Self::BeneficiaryCommitments => "beneficiary_commitments",
            Self::RelayConfirmationRoots => "relay_confirmation_roots",
            Self::ReorgSafety => "reorg_safety",
            Self::FeeRebateNetting => "fee_rebate_netting",
            Self::CircuitBreakers => "circuit_breakers",
            Self::LiveHeavyGateEvidence => "live_heavy_gate_evidence",
            Self::OperatorSignoff => "operator_signoff",
            Self::ReviewerSignoff => "reviewer_signoff",
            Self::ReleaseCreditAccounting => "release_credit_accounting",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateStatus {
    Missing,
    Blocked,
    Clear,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Blocked => "blocked",
            Self::Clear => "clear",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlockerKind {
    HeavyGatesNotRun,
    ReleaseCreditDisabled,
    CreditAccountingDisabled,
    PqAuthorizationRootMissing,
    PqAuthorityCountLow,
    PqQuorumLow,
    ReserveBalanceProofMissing,
    ReserveCoverageLow,
    ReserveProofDepthLow,
    AmountBucketRootMissing,
    AmountBucketTooSmall,
    BeneficiaryCommitmentRootMissing,
    BeneficiaryCommitmentCountLow,
    RelayConfirmationRootMissing,
    RelayConfirmationDepthLow,
    RelayConfirmationCountLow,
    ReorgSafetyRootMissing,
    ReorgSafetyDepthLow,
    ReorgRiskHigh,
    FeeRebateNettingRootMissing,
    FeeRebateDriftNonZero,
    CircuitBreakerRootMissing,
    CircuitBreakerOpen,
    LiveHeavyGateEvidenceMissing,
    LiveHeavyGateEvidenceCountLow,
    OperatorSignoffMissing,
    ReviewerSignoffMissing,
    RootsOnlyBoundary,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeavyGatesNotRun => "heavy_gates_not_run",
            Self::ReleaseCreditDisabled => "release_credit_disabled",
            Self::CreditAccountingDisabled => "credit_accounting_disabled",
            Self::PqAuthorizationRootMissing => "pq_authorization_root_missing",
            Self::PqAuthorityCountLow => "pq_authority_count_low",
            Self::PqQuorumLow => "pq_quorum_low",
            Self::ReserveBalanceProofMissing => "reserve_balance_proof_missing",
            Self::ReserveCoverageLow => "reserve_coverage_low",
            Self::ReserveProofDepthLow => "reserve_proof_depth_low",
            Self::AmountBucketRootMissing => "amount_bucket_root_missing",
            Self::AmountBucketTooSmall => "amount_bucket_too_small",
            Self::BeneficiaryCommitmentRootMissing => "beneficiary_commitment_root_missing",
            Self::BeneficiaryCommitmentCountLow => "beneficiary_commitment_count_low",
            Self::RelayConfirmationRootMissing => "relay_confirmation_root_missing",
            Self::RelayConfirmationDepthLow => "relay_confirmation_depth_low",
            Self::RelayConfirmationCountLow => "relay_confirmation_count_low",
            Self::ReorgSafetyRootMissing => "reorg_safety_root_missing",
            Self::ReorgSafetyDepthLow => "reorg_safety_depth_low",
            Self::ReorgRiskHigh => "reorg_risk_high",
            Self::FeeRebateNettingRootMissing => "fee_rebate_netting_root_missing",
            Self::FeeRebateDriftNonZero => "fee_rebate_drift_non_zero",
            Self::CircuitBreakerRootMissing => "circuit_breaker_root_missing",
            Self::CircuitBreakerOpen => "circuit_breaker_open",
            Self::LiveHeavyGateEvidenceMissing => "live_heavy_gate_evidence_missing",
            Self::LiveHeavyGateEvidenceCountLow => "live_heavy_gate_evidence_count_low",
            Self::OperatorSignoffMissing => "operator_signoff_missing",
            Self::ReviewerSignoffMissing => "reviewer_signoff_missing",
            Self::RootsOnlyBoundary => "roots_only_boundary",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub lane_id: String,
    pub lane_kind: String,
    pub wave: u64,
    pub previous_confirmation_wave: u64,
    pub min_pq_authority_count: u64,
    pub min_pq_quorum_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub min_reserve_proof_depth: u64,
    pub min_amount_bucket_size: u64,
    pub min_beneficiary_commitments: u64,
    pub min_relay_confirmation_depth: u64,
    pub min_relay_confirmation_roots: u64,
    pub min_reorg_safety_depth: u64,
    pub max_reorg_risk_bps: u64,
    pub max_fee_rebate_drift_piconero: i128,
    pub min_heavy_gate_evidence_count: u64,
    pub min_signoff_count: u64,
    pub release_credit_allowed: bool,
    pub credit_accounting_allowed: bool,
    pub heavy_gates_ran: bool,
    pub circuit_breakers_open: bool,
    pub roots_only_public_records: bool,
    pub deny_when_any_blocker_active: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            lane_id: LANE_ID.to_string(),
            lane_kind: "pq_reserve_privacy".to_string(),
            wave: WAVE,
            previous_confirmation_wave: PREVIOUS_CONFIRMATION_WAVE,
            min_pq_authority_count: MIN_PQ_AUTHORITY_COUNT,
            min_pq_quorum_bps: MIN_PQ_QUORUM_BPS,
            min_reserve_coverage_bps: MIN_RESERVE_COVERAGE_BPS,
            min_reserve_proof_depth: MIN_RESERVE_PROOF_DEPTH,
            min_amount_bucket_size: MIN_AMOUNT_BUCKET_SIZE,
            min_beneficiary_commitments: MIN_BENEFICIARY_COMMITMENTS,
            min_relay_confirmation_depth: MIN_RELAY_CONFIRMATION_DEPTH,
            min_relay_confirmation_roots: MIN_RELAY_CONFIRMATION_ROOTS,
            min_reorg_safety_depth: MIN_REORG_SAFETY_DEPTH,
            max_reorg_risk_bps: MAX_REORG_RISK_BPS,
            max_fee_rebate_drift_piconero: MAX_FEE_REBATE_DRIFT_PICONERO,
            min_heavy_gate_evidence_count: MIN_HEAVY_GATE_EVIDENCE_COUNT,
            min_signoff_count: MIN_SIGNOFF_COUNT,
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
            circuit_breakers_open: true,
            roots_only_public_records: true,
            deny_when_any_blocker_active: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> PublicRecord {
        let mut out = JsonObject::new();
        out.field_str("chain_id", &self.chain_id);
        out.field_str("protocol_version", &self.protocol_version);
        out.field_str("lane_id", &self.lane_id);
        out.field_str("lane_kind", &self.lane_kind);
        out.field_num("wave", self.wave);
        out.field_num(
            "previous_confirmation_wave",
            self.previous_confirmation_wave,
        );
        out.field_bool("release_credit_allowed", self.release_credit_allowed);
        out.field_bool("credit_accounting_allowed", self.credit_accounting_allowed);
        out.field_bool("heavy_gates_ran", self.heavy_gates_ran);
        out.field_bool("circuit_breakers_open", self.circuit_breakers_open);
        out.field_bool("roots_only_public_records", self.roots_only_public_records);
        out.field_bool(
            "deny_when_any_blocker_active",
            self.deny_when_any_blocker_active,
        );
        out.finish()
    }

    pub fn state_root(&self) -> String {
        stable_hash("config", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRoots {
    pub pq_authorization_root: String,
    pub pq_rotation_root: String,
    pub reserve_balance_proof_root: String,
    pub reserve_liability_root: String,
    pub amount_bucket_privacy_root: String,
    pub beneficiary_commitment_root: String,
    pub relay_confirmation_root: String,
    pub relay_witness_root: String,
    pub monero_inclusion_root: String,
    pub reorg_safety_root: String,
    pub fee_rebate_netting_root: String,
    pub circuit_breaker_root: String,
    pub live_heavy_gate_evidence_root: String,
    pub operator_signoff_root: String,
    pub reviewer_signoff_root: String,
}

impl Default for EvidenceRoots {
    fn default() -> Self {
        Self {
            pq_authorization_root: String::new(),
            pq_rotation_root: String::new(),
            reserve_balance_proof_root: String::new(),
            reserve_liability_root: String::new(),
            amount_bucket_privacy_root: String::new(),
            beneficiary_commitment_root: String::new(),
            relay_confirmation_root: String::new(),
            relay_witness_root: String::new(),
            monero_inclusion_root: String::new(),
            reorg_safety_root: String::new(),
            fee_rebate_netting_root: String::new(),
            circuit_breaker_root: String::new(),
            live_heavy_gate_evidence_root: String::new(),
            operator_signoff_root: String::new(),
            reviewer_signoff_root: String::new(),
        }
    }
}

impl EvidenceRoots {
    pub fn public_record(&self) -> PublicRecord {
        let mut out = JsonObject::new();
        out.field_str(
            "pq_authorization_root",
            redact_root(&self.pq_authorization_root),
        );
        out.field_str("pq_rotation_root", redact_root(&self.pq_rotation_root));
        out.field_str(
            "reserve_balance_proof_root",
            redact_root(&self.reserve_balance_proof_root),
        );
        out.field_str(
            "reserve_liability_root",
            redact_root(&self.reserve_liability_root),
        );
        out.field_str(
            "amount_bucket_privacy_root",
            redact_root(&self.amount_bucket_privacy_root),
        );
        out.field_str(
            "beneficiary_commitment_root",
            redact_root(&self.beneficiary_commitment_root),
        );
        out.field_str(
            "relay_confirmation_root",
            redact_root(&self.relay_confirmation_root),
        );
        out.field_str("relay_witness_root", redact_root(&self.relay_witness_root));
        out.field_str(
            "monero_inclusion_root",
            redact_root(&self.monero_inclusion_root),
        );
        out.field_str("reorg_safety_root", redact_root(&self.reorg_safety_root));
        out.field_str(
            "fee_rebate_netting_root",
            redact_root(&self.fee_rebate_netting_root),
        );
        out.field_str(
            "circuit_breaker_root",
            redact_root(&self.circuit_breaker_root),
        );
        out.field_str(
            "live_heavy_gate_evidence_root",
            redact_root(&self.live_heavy_gate_evidence_root),
        );
        out.field_str(
            "operator_signoff_root",
            redact_root(&self.operator_signoff_root),
        );
        out.field_str(
            "reviewer_signoff_root",
            redact_root(&self.reviewer_signoff_root),
        );
        out.finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateMetrics {
    pub pq_authority_count: u64,
    pub pq_quorum_bps: u64,
    pub reserve_coverage_bps: u64,
    pub reserve_proof_depth: u64,
    pub amount_bucket_size: u64,
    pub beneficiary_commitment_count: u64,
    pub relay_confirmation_depth: u64,
    pub relay_confirmation_root_count: u64,
    pub reorg_safety_depth: u64,
    pub reorg_risk_bps: u64,
    pub fee_rebate_drift_piconero: i128,
    pub live_heavy_gate_evidence_count: u64,
    pub operator_signoff_count: u64,
    pub reviewer_signoff_count: u64,
}

impl Default for GateMetrics {
    fn default() -> Self {
        Self {
            pq_authority_count: 0,
            pq_quorum_bps: 0,
            reserve_coverage_bps: 0,
            reserve_proof_depth: 0,
            amount_bucket_size: 0,
            beneficiary_commitment_count: 0,
            relay_confirmation_depth: 0,
            relay_confirmation_root_count: 0,
            reorg_safety_depth: 0,
            reorg_risk_bps: u64::MAX,
            fee_rebate_drift_piconero: 1,
            live_heavy_gate_evidence_count: 0,
            operator_signoff_count: 0,
            reviewer_signoff_count: 0,
        }
    }
}

impl GateMetrics {
    pub fn public_record(&self) -> PublicRecord {
        let mut out = JsonObject::new();
        out.field_num("pq_authority_count", self.pq_authority_count);
        out.field_num("pq_quorum_bps", self.pq_quorum_bps);
        out.field_num("reserve_coverage_bps", self.reserve_coverage_bps);
        out.field_num("reserve_proof_depth", self.reserve_proof_depth);
        out.field_num("amount_bucket_size", self.amount_bucket_size);
        out.field_num(
            "beneficiary_commitment_count",
            self.beneficiary_commitment_count,
        );
        out.field_num("relay_confirmation_depth", self.relay_confirmation_depth);
        out.field_num(
            "relay_confirmation_root_count",
            self.relay_confirmation_root_count,
        );
        out.field_num("reorg_safety_depth", self.reorg_safety_depth);
        out.field_num("reorg_risk_bps", self.reorg_risk_bps);
        out.field_raw(
            "fee_rebate_drift_piconero",
            &self.fee_rebate_drift_piconero.to_string(),
        );
        out.field_num(
            "live_heavy_gate_evidence_count",
            self.live_heavy_gate_evidence_count,
        );
        out.field_num("operator_signoff_count", self.operator_signoff_count);
        out.field_num("reviewer_signoff_count", self.reviewer_signoff_count);
        out.finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateRecord {
    pub kind: GateKind,
    pub status: GateStatus,
    pub root: String,
    pub blockers: Vec<BlockerKind>,
}

impl GateRecord {
    pub fn evaluate(
        config: &Config,
        roots: &EvidenceRoots,
        metrics: &GateMetrics,
        kind: GateKind,
    ) -> Self {
        let blockers = blockers_for_kind(config, roots, metrics, kind);
        let status = if blockers.is_empty() {
            GateStatus::Clear
        } else if has_missing_root(&blockers) {
            GateStatus::Missing
        } else {
            GateStatus::Blocked
        };
        Self {
            kind,
            status,
            root: root_for_kind(roots, kind).to_string(),
            blockers,
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        let mut out = JsonObject::new();
        out.field_str("kind", self.kind.as_str());
        out.field_str("status", self.status.as_str());
        out.field_str("root", redact_root(&self.root));
        out.field_raw("blockers", &blockers_json(&self.blockers));
        out.finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub roots: EvidenceRoots,
    pub metrics: GateMetrics,
    pub records: Vec<GateRecord>,
    pub active_blockers: Vec<BlockerKind>,
    pub release_credit_allowed: bool,
    pub credit_accounting_allowed: bool,
    pub heavy_gates_ran: bool,
    pub verdict: String,
}

impl State {
    pub fn new(config: Config, roots: EvidenceRoots, metrics: GateMetrics) -> Result<Self> {
        let records = GateKind::all()
            .iter()
            .map(|kind| GateRecord::evaluate(&config, &roots, &metrics, *kind))
            .collect::<Vec<_>>();
        validate_records(&records)?;
        let active_blockers = active_blockers(&config, &roots, &metrics);
        let release_credit_allowed = config.release_credit_allowed
            && active_blockers.is_empty()
            && !config.circuit_breakers_open;
        let credit_accounting_allowed = config.credit_accounting_allowed
            && release_credit_allowed
            && active_blockers.is_empty()
            && config.heavy_gates_ran;
        let heavy_gates_ran = config.heavy_gates_ran;
        let verdict = if !release_credit_allowed || !credit_accounting_allowed {
            "fail_closed"
        } else if config.deny_when_any_blocker_active && !active_blockers.is_empty() {
            "blocked"
        } else {
            "shadow_clear"
        };
        Ok(Self {
            config,
            roots,
            metrics,
            records,
            active_blockers,
            release_credit_allowed,
            credit_accounting_allowed,
            heavy_gates_ran,
            verdict: verdict.to_string(),
        })
    }

    pub fn fail_closed(reason: &str) -> Self {
        let config = Config::default();
        let roots = EvidenceRoots::default();
        let metrics = GateMetrics::default();
        let mut records = GateKind::all()
            .iter()
            .map(|kind| GateRecord::evaluate(&config, &roots, &metrics, *kind))
            .collect::<Vec<_>>();
        records.push(GateRecord {
            kind: GateKind::ReleaseCreditAccounting,
            status: GateStatus::Blocked,
            root: stable_hash("fail_closed_reason", reason),
            blockers: vec![
                BlockerKind::ReleaseCreditDisabled,
                BlockerKind::CreditAccountingDisabled,
                BlockerKind::RootsOnlyBoundary,
            ],
        });
        Self {
            active_blockers: active_blockers(&config, &roots, &metrics),
            config,
            roots,
            metrics,
            records,
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
            verdict: "fail_closed".to_string(),
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        let mut out = JsonObject::new();
        out.field_str("chain_id", &self.config.chain_id);
        out.field_str("protocol_version", &self.config.protocol_version);
        out.field_str("lane_id", &self.config.lane_id);
        out.field_str("lane_kind", &self.config.lane_kind);
        out.field_num("wave", self.config.wave);
        out.field_str("verdict", &self.verdict);
        out.field_bool("release_credit_allowed", self.release_credit_allowed);
        out.field_bool("credit_accounting_allowed", self.credit_accounting_allowed);
        out.field_bool("heavy_gates_ran", self.heavy_gates_ran);
        out.field_bool(
            "roots_only_public_records",
            self.config.roots_only_public_records,
        );
        out.field_raw("config", &self.config.public_record());
        out.field_raw("roots", &self.roots.public_record());
        out.field_raw("metrics", &self.metrics.public_record());
        out.field_raw("records", &records_json(&self.records));
        out.field_raw("active_blockers", &blockers_json(&self.active_blockers));
        out.field_str("state_root", &self.state_root_core());
        out.finish()
    }

    pub fn state_root(&self) -> String {
        stable_hash("state", &self.public_record())
    }

    fn state_root_core(&self) -> String {
        let mut core = String::new();
        core.push_str(&self.config.state_root());
        core.push('|');
        core.push_str(&stable_hash("roots", &self.roots.public_record()));
        core.push('|');
        core.push_str(&stable_hash("metrics", &self.metrics.public_record()));
        core.push('|');
        core.push_str(&stable_hash("records", &records_json(&self.records)));
        core.push('|');
        core.push_str(&stable_hash(
            "blockers",
            &blockers_json(&self.active_blockers),
        ));
        stable_hash("state_core", &core)
    }
}

pub fn devnet() -> Runtime {
    match State::new(
        Config::default(),
        EvidenceRoots::devnet(),
        GateMetrics::default(),
    ) {
        Ok(state) => state,
        Err(_) => State::fail_closed("state_new_error"),
    }
}

pub fn public_record() -> PublicRecord {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn active_blockers(
    config: &Config,
    roots: &EvidenceRoots,
    metrics: &GateMetrics,
) -> Vec<BlockerKind> {
    let mut set = BTreeSet::new();
    for kind in GateKind::all() {
        for blocker in blockers_for_kind(config, roots, metrics, kind) {
            set.insert(blocker);
        }
    }
    set.into_iter().collect()
}

fn blockers_for_kind(
    config: &Config,
    roots: &EvidenceRoots,
    metrics: &GateMetrics,
    kind: GateKind,
) -> Vec<BlockerKind> {
    let mut blockers = Vec::new();
    if !config.heavy_gates_ran {
        blockers.push(BlockerKind::HeavyGatesNotRun);
    }
    match kind {
        GateKind::PqAuthorizationRoots => {
            if roots.pq_authorization_root.is_empty() || roots.pq_rotation_root.is_empty() {
                blockers.push(BlockerKind::PqAuthorizationRootMissing);
            }
            if metrics.pq_authority_count < config.min_pq_authority_count {
                blockers.push(BlockerKind::PqAuthorityCountLow);
            }
            if metrics.pq_quorum_bps < config.min_pq_quorum_bps {
                blockers.push(BlockerKind::PqQuorumLow);
            }
        }
        GateKind::ReserveBalanceProofs => {
            if roots.reserve_balance_proof_root.is_empty()
                || roots.reserve_liability_root.is_empty()
            {
                blockers.push(BlockerKind::ReserveBalanceProofMissing);
            }
            if metrics.reserve_coverage_bps < config.min_reserve_coverage_bps {
                blockers.push(BlockerKind::ReserveCoverageLow);
            }
            if metrics.reserve_proof_depth < config.min_reserve_proof_depth {
                blockers.push(BlockerKind::ReserveProofDepthLow);
            }
        }
        GateKind::AmountBucketPrivacy => {
            if roots.amount_bucket_privacy_root.is_empty() {
                blockers.push(BlockerKind::AmountBucketRootMissing);
            }
            if metrics.amount_bucket_size < config.min_amount_bucket_size {
                blockers.push(BlockerKind::AmountBucketTooSmall);
            }
        }
        GateKind::BeneficiaryCommitments => {
            if roots.beneficiary_commitment_root.is_empty() {
                blockers.push(BlockerKind::BeneficiaryCommitmentRootMissing);
            }
            if metrics.beneficiary_commitment_count < config.min_beneficiary_commitments {
                blockers.push(BlockerKind::BeneficiaryCommitmentCountLow);
            }
        }
        GateKind::RelayConfirmationRoots => {
            if roots.relay_confirmation_root.is_empty()
                || roots.relay_witness_root.is_empty()
                || roots.monero_inclusion_root.is_empty()
            {
                blockers.push(BlockerKind::RelayConfirmationRootMissing);
            }
            if metrics.relay_confirmation_depth < config.min_relay_confirmation_depth {
                blockers.push(BlockerKind::RelayConfirmationDepthLow);
            }
            if metrics.relay_confirmation_root_count < config.min_relay_confirmation_roots {
                blockers.push(BlockerKind::RelayConfirmationCountLow);
            }
        }
        GateKind::ReorgSafety => {
            if roots.reorg_safety_root.is_empty() {
                blockers.push(BlockerKind::ReorgSafetyRootMissing);
            }
            if metrics.reorg_safety_depth < config.min_reorg_safety_depth {
                blockers.push(BlockerKind::ReorgSafetyDepthLow);
            }
            if metrics.reorg_risk_bps > config.max_reorg_risk_bps {
                blockers.push(BlockerKind::ReorgRiskHigh);
            }
        }
        GateKind::FeeRebateNetting => {
            if roots.fee_rebate_netting_root.is_empty() {
                blockers.push(BlockerKind::FeeRebateNettingRootMissing);
            }
            if metrics.fee_rebate_drift_piconero != config.max_fee_rebate_drift_piconero {
                blockers.push(BlockerKind::FeeRebateDriftNonZero);
            }
        }
        GateKind::CircuitBreakers => {
            if roots.circuit_breaker_root.is_empty() {
                blockers.push(BlockerKind::CircuitBreakerRootMissing);
            }
            if config.circuit_breakers_open {
                blockers.push(BlockerKind::CircuitBreakerOpen);
            }
        }
        GateKind::LiveHeavyGateEvidence => {
            if roots.live_heavy_gate_evidence_root.is_empty() {
                blockers.push(BlockerKind::LiveHeavyGateEvidenceMissing);
            }
            if metrics.live_heavy_gate_evidence_count < config.min_heavy_gate_evidence_count {
                blockers.push(BlockerKind::LiveHeavyGateEvidenceCountLow);
            }
        }
        GateKind::OperatorSignoff => {
            if roots.operator_signoff_root.is_empty()
                || metrics.operator_signoff_count < config.min_signoff_count
            {
                blockers.push(BlockerKind::OperatorSignoffMissing);
            }
        }
        GateKind::ReviewerSignoff => {
            if roots.reviewer_signoff_root.is_empty()
                || metrics.reviewer_signoff_count < config.min_signoff_count
            {
                blockers.push(BlockerKind::ReviewerSignoffMissing);
            }
        }
        GateKind::ReleaseCreditAccounting => {
            if !config.release_credit_allowed {
                blockers.push(BlockerKind::ReleaseCreditDisabled);
            }
            if !config.credit_accounting_allowed {
                blockers.push(BlockerKind::CreditAccountingDisabled);
            }
            if config.roots_only_public_records {
                blockers.push(BlockerKind::RootsOnlyBoundary);
            }
        }
    }
    blockers
}

fn root_for_kind(roots: &EvidenceRoots, kind: GateKind) -> &str {
    match kind {
        GateKind::PqAuthorizationRoots => &roots.pq_authorization_root,
        GateKind::ReserveBalanceProofs => &roots.reserve_balance_proof_root,
        GateKind::AmountBucketPrivacy => &roots.amount_bucket_privacy_root,
        GateKind::BeneficiaryCommitments => &roots.beneficiary_commitment_root,
        GateKind::RelayConfirmationRoots => &roots.relay_confirmation_root,
        GateKind::ReorgSafety => &roots.reorg_safety_root,
        GateKind::FeeRebateNetting => &roots.fee_rebate_netting_root,
        GateKind::CircuitBreakers => &roots.circuit_breaker_root,
        GateKind::LiveHeavyGateEvidence => &roots.live_heavy_gate_evidence_root,
        GateKind::OperatorSignoff => &roots.operator_signoff_root,
        GateKind::ReviewerSignoff => &roots.reviewer_signoff_root,
        GateKind::ReleaseCreditAccounting => &roots.fee_rebate_netting_root,
    }
}

fn has_missing_root(blockers: &[BlockerKind]) -> bool {
    blockers.iter().any(|blocker| {
        matches!(
            blocker,
            BlockerKind::PqAuthorizationRootMissing
                | BlockerKind::ReserveBalanceProofMissing
                | BlockerKind::AmountBucketRootMissing
                | BlockerKind::BeneficiaryCommitmentRootMissing
                | BlockerKind::RelayConfirmationRootMissing
                | BlockerKind::ReorgSafetyRootMissing
                | BlockerKind::FeeRebateNettingRootMissing
                | BlockerKind::CircuitBreakerRootMissing
                | BlockerKind::LiveHeavyGateEvidenceMissing
        )
    })
}

fn validate_records(records: &[GateRecord]) -> Result<()> {
    if records.len() > MAX_RECORDS {
        return Err(RuntimeError::RecordLimitExceeded);
    }
    let mut seen = BTreeSet::new();
    for record in records {
        if record.root.is_empty() && record.status == GateStatus::Clear {
            return Err(RuntimeError::EmptyRecordRoot);
        }
        let key = format!("{}:{}", record.kind.as_str(), record.root);
        if !seen.insert(key) {
            return Err(RuntimeError::DuplicateRecordRoot);
        }
    }
    Ok(())
}

fn records_json(records: &[GateRecord]) -> String {
    let mut out = String::from("[");
    for (index, record) in records.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&record.public_record());
    }
    out.push(']');
    out
}

fn blockers_json(blockers: &[BlockerKind]) -> String {
    let mut out = String::from("[");
    for (index, blocker) in blockers.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(blocker.as_str());
        out.push('"');
    }
    out.push(']');
    out
}

fn redact_root(root: &str) -> &str {
    if root.is_empty() {
        "missing"
    } else {
        root
    }
}

fn stable_hash(domain: &str, value: &str) -> String {
    let mut h0: u64 = 0x243f_6a88_85a3_08d3;
    let mut h1: u64 = 0x1319_8a2e_0370_7344;
    let mut h2: u64 = 0xa409_3822_299f_31d0;
    let mut h3: u64 = 0x082e_fa98_ec4e_6c89;
    for byte in domain.bytes().chain([0xff]).chain(value.bytes()) {
        let b = u64::from(byte);
        h0 = h0.rotate_left(5) ^ b.wrapping_mul(0x1000_0000_01b3);
        h1 = h1.rotate_left(7).wrapping_add(h0 ^ b);
        h2 = h2.rotate_left(11) ^ h1.wrapping_mul(0x9e37_79b1_85eb_ca87);
        h3 = h3.rotate_left(13).wrapping_add(h2 ^ h0);
    }
    format!("{h0:016x}{h1:016x}{h2:016x}{h3:016x}")
}

struct JsonObject {
    text: String,
    first: bool,
}

impl JsonObject {
    fn new() -> Self {
        Self {
            text: String::from("{"),
            first: true,
        }
    }

    fn sep(&mut self) {
        if self.first {
            self.first = false;
        } else {
            self.text.push(',');
        }
    }

    fn field_str(&mut self, key: &str, value: &str) {
        self.sep();
        self.text.push('"');
        self.text.push_str(key);
        self.text.push_str("\": ");
        self.text.push('"');
        self.text.push_str(&escape_json(value));
        self.text.push('"');
    }

    fn field_num(&mut self, key: &str, value: u64) {
        self.sep();
        self.text.push('"');
        self.text.push_str(key);
        self.text.push_str("\": ");
        self.text.push_str(&value.to_string());
    }

    fn field_bool(&mut self, key: &str, value: bool) {
        self.sep();
        self.text.push('"');
        self.text.push_str(key);
        self.text.push_str("\": ");
        if value {
            self.text.push_str("true");
        } else {
            self.text.push_str("false");
        }
    }

    fn field_raw(&mut self, key: &str, value: &str) {
        self.sep();
        self.text.push('"');
        self.text.push_str(key);
        self.text.push_str("\": ");
        self.text.push_str(value);
    }

    fn finish(mut self) -> String {
        self.text.push('}');
        self.text
    }
}

fn escape_json(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}
