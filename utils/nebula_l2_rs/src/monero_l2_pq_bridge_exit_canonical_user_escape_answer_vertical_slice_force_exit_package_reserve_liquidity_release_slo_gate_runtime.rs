use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageReserveLiquidityReleaseSloGateRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RESERVE_LIQUIDITY_RELEASE_SLO_GATE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-reserve-liquidity-release-slo-gate-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RESERVE_LIQUIDITY_RELEASE_SLO_GATE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_SLO_GATE_SUITE: &str =
    "monero-l2-pq-bridge-exit-force-exit-package-reserve-liquidity-release-slo-gate-v1";
pub const DEFAULT_RESERVE_UNIT: u64 = 1_000_000;
pub const DEFAULT_MIN_RELEASE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MIN_BUFFER_BPS: u64 = 1_500;
pub const DEFAULT_MAX_RELEASE_LATENCY_SECONDS: u64 = 1_800;
pub const DEFAULT_MAX_STRESS_DRAWDOWN_BPS: u64 = 2_000;
pub const DEFAULT_REQUIRED_GATE_RECORDS: u64 = 6;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub release_slo_gate_suite: String,
    pub reserve_unit: u64,
    pub min_release_coverage_bps: u64,
    pub min_buffer_bps: u64,
    pub max_release_latency_seconds: u64,
    pub max_stress_drawdown_bps: u64,
    pub required_gate_records: u64,
    pub require_zero_breach_roots: bool,
    pub require_fee_rebate_liability_coverage: bool,
    pub require_hold_on_stress_breach: bool,
    pub roots_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            release_slo_gate_suite: RELEASE_SLO_GATE_SUITE.to_string(),
            reserve_unit: DEFAULT_RESERVE_UNIT,
            min_release_coverage_bps: DEFAULT_MIN_RELEASE_COVERAGE_BPS,
            min_buffer_bps: DEFAULT_MIN_BUFFER_BPS,
            max_release_latency_seconds: DEFAULT_MAX_RELEASE_LATENCY_SECONDS,
            max_stress_drawdown_bps: DEFAULT_MAX_STRESS_DRAWDOWN_BPS,
            required_gate_records: DEFAULT_REQUIRED_GATE_RECORDS,
            require_zero_breach_roots: true,
            require_fee_rebate_liability_coverage: true,
            require_hold_on_stress_breach: true,
            roots_only: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "release_slo_gate_suite": self.release_slo_gate_suite,
            "reserve_unit": self.reserve_unit,
            "min_release_coverage_bps": self.min_release_coverage_bps,
            "min_buffer_bps": self.min_buffer_bps,
            "max_release_latency_seconds": self.max_release_latency_seconds,
            "max_stress_drawdown_bps": self.max_stress_drawdown_bps,
            "required_gate_records": self.required_gate_records,
            "require_zero_breach_roots": self.require_zero_breach_roots,
            "require_fee_rebate_liability_coverage": self.require_fee_rebate_liability_coverage,
            "require_hold_on_stress_breach": self.require_hold_on_stress_breach,
            "roots_only": self.roots_only,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateLane {
    ReserveProof,
    WithdrawalQueue,
    LiquidityBuffer,
    FeeRebateLiability,
    TimeToReleaseSlo,
    StressScenario,
}

impl GateLane {
    pub fn ordered() -> &'static [Self] {
        &[
            Self::ReserveProof,
            Self::WithdrawalQueue,
            Self::LiquidityBuffer,
            Self::FeeRebateLiability,
            Self::TimeToReleaseSlo,
            Self::StressScenario,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveProof => "reserve_proof",
            Self::WithdrawalQueue => "withdrawal_queue",
            Self::LiquidityBuffer => "liquidity_buffer",
            Self::FeeRebateLiability => "fee_rebate_liability",
            Self::TimeToReleaseSlo => "time_to_release_slo",
            Self::StressScenario => "stress_scenario",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReleaseVerdict {
    ReleaseAllowed,
    HoldRequired,
}

impl HoldReleaseVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseAllowed => "release_allowed",
            Self::HoldRequired => "hold_required",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub gate_record_count: u64,
    pub release_allowed_count: u64,
    pub hold_required_count: u64,
    pub breach_count: u64,
    pub reserve_proof_count: u64,
    pub withdrawal_queue_count: u64,
    pub liquidity_buffer_count: u64,
    pub fee_rebate_liability_count: u64,
    pub time_to_release_slo_count: u64,
    pub stress_scenario_count: u64,
    pub total_reserve_units: u64,
    pub total_withdrawal_queue_units: u64,
    pub total_liquidity_buffer_units: u64,
    pub total_fee_rebate_liability_units: u64,
}

impl Counters {
    pub fn from_records(records: &[ReleaseSloGateRecord]) -> Self {
        let mut counters = Self {
            gate_record_count: records.len() as u64,
            ..Self::default()
        };
        for record in records {
            counters.total_reserve_units = counters
                .total_reserve_units
                .saturating_add(record.reserve_units);
            counters.total_withdrawal_queue_units = counters
                .total_withdrawal_queue_units
                .saturating_add(record.withdrawal_queue_units);
            counters.total_liquidity_buffer_units = counters
                .total_liquidity_buffer_units
                .saturating_add(record.liquidity_buffer_units);
            counters.total_fee_rebate_liability_units = counters
                .total_fee_rebate_liability_units
                .saturating_add(record.fee_rebate_liability_units);
            counters.breach_count = counters.breach_count.saturating_add(record.breach_count);
            match record.hold_release_verdict {
                HoldReleaseVerdict::ReleaseAllowed => counters.release_allowed_count += 1,
                HoldReleaseVerdict::HoldRequired => counters.hold_required_count += 1,
            }
            match record.lane {
                GateLane::ReserveProof => counters.reserve_proof_count += 1,
                GateLane::WithdrawalQueue => counters.withdrawal_queue_count += 1,
                GateLane::LiquidityBuffer => counters.liquidity_buffer_count += 1,
                GateLane::FeeRebateLiability => counters.fee_rebate_liability_count += 1,
                GateLane::TimeToReleaseSlo => counters.time_to_release_slo_count += 1,
                GateLane::StressScenario => counters.stress_scenario_count += 1,
            }
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseSloGateRecord {
    pub gate_id: String,
    pub ordinal: u64,
    pub lane: GateLane,
    pub reserve_proof_root: String,
    pub withdrawal_queue_root: String,
    pub liquidity_buffer_root: String,
    pub fee_rebate_liability_root: String,
    pub time_to_release_slo_root: String,
    pub stress_scenario_root: String,
    pub breach_root: String,
    pub hold_release_verdict_root: String,
    pub reserve_units: u64,
    pub withdrawal_queue_units: u64,
    pub liquidity_buffer_units: u64,
    pub fee_rebate_liability_units: u64,
    pub release_latency_seconds: u64,
    pub stress_drawdown_bps: u64,
    pub coverage_bps: u64,
    pub buffer_bps: u64,
    pub breach_count: u64,
    pub hold_release_verdict: HoldReleaseVerdict,
    pub gate_root: String,
}

impl ReleaseSloGateRecord {
    pub fn devnet(config: &Config, lane: GateLane, ordinal: u64) -> Self {
        let withdrawal_queue_units = withdrawal_queue_units(config, lane);
        let fee_rebate_liability_units = fee_rebate_liability_units(config, lane);
        let reserve_units = reserve_units(config, lane, withdrawal_queue_units);
        let liquidity_buffer_units = liquidity_buffer_units(config, lane);
        let release_latency_seconds = release_latency_seconds(config, lane);
        let stress_drawdown_bps = stress_drawdown_bps(config, lane);
        let total_liability_units =
            withdrawal_queue_units.saturating_add(fee_rebate_liability_units);
        let coverage_bps = bps(reserve_units, total_liability_units);
        let buffer_bps = bps(liquidity_buffer_units, withdrawal_queue_units);
        let breach_count = breach_count(
            config,
            coverage_bps,
            buffer_bps,
            release_latency_seconds,
            stress_drawdown_bps,
        );
        let hold_release_verdict = if breach_count == 0 {
            HoldReleaseVerdict::ReleaseAllowed
        } else {
            HoldReleaseVerdict::HoldRequired
        };
        let reserve_proof_root = lane_metric_root(
            config,
            lane,
            "reserve-proof",
            reserve_units,
            total_liability_units,
            coverage_bps,
        );
        let withdrawal_queue_root = lane_metric_root(
            config,
            lane,
            "withdrawal-queue",
            withdrawal_queue_units,
            reserve_units,
            bps(withdrawal_queue_units, reserve_units),
        );
        let liquidity_buffer_root = lane_metric_root(
            config,
            lane,
            "liquidity-buffer",
            liquidity_buffer_units,
            withdrawal_queue_units,
            buffer_bps,
        );
        let fee_rebate_liability_root = lane_metric_root(
            config,
            lane,
            "fee-rebate-liability",
            fee_rebate_liability_units,
            reserve_units,
            bps(fee_rebate_liability_units, reserve_units),
        );
        let time_to_release_slo_root = lane_metric_root(
            config,
            lane,
            "time-to-release-slo",
            release_latency_seconds,
            config.max_release_latency_seconds,
            if release_latency_seconds <= config.max_release_latency_seconds {
                10_000
            } else {
                bps(config.max_release_latency_seconds, release_latency_seconds)
            },
        );
        let stress_scenario_root = lane_metric_root(
            config,
            lane,
            "stress-scenario",
            stress_drawdown_bps,
            config.max_stress_drawdown_bps,
            bps(config.max_stress_drawdown_bps, stress_drawdown_bps.max(1)),
        );
        let breach_root = breach_root(
            config,
            lane,
            coverage_bps,
            buffer_bps,
            release_latency_seconds,
            stress_drawdown_bps,
            breach_count,
        );
        let hold_release_verdict_root = hold_release_verdict_root(
            config,
            lane,
            hold_release_verdict,
            breach_count,
            &breach_root,
        );
        let gate_root = gate_record_root(
            config,
            lane,
            ordinal,
            &reserve_proof_root,
            &withdrawal_queue_root,
            &liquidity_buffer_root,
            &fee_rebate_liability_root,
            &time_to_release_slo_root,
            &stress_scenario_root,
            &breach_root,
            &hold_release_verdict_root,
            hold_release_verdict,
        );
        let gate_id = gate_id(lane, ordinal, &gate_root);
        Self {
            gate_id,
            ordinal,
            lane,
            reserve_proof_root,
            withdrawal_queue_root,
            liquidity_buffer_root,
            fee_rebate_liability_root,
            time_to_release_slo_root,
            stress_scenario_root,
            breach_root,
            hold_release_verdict_root,
            reserve_units,
            withdrawal_queue_units,
            liquidity_buffer_units,
            fee_rebate_liability_units,
            release_latency_seconds,
            stress_drawdown_bps,
            coverage_bps,
            buffer_bps,
            breach_count,
            hold_release_verdict,
            gate_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "ordinal": self.ordinal,
            "lane": self.lane.as_str(),
            "reserve_proof_root": self.reserve_proof_root,
            "withdrawal_queue_root": self.withdrawal_queue_root,
            "liquidity_buffer_root": self.liquidity_buffer_root,
            "fee_rebate_liability_root": self.fee_rebate_liability_root,
            "time_to_release_slo_root": self.time_to_release_slo_root,
            "stress_scenario_root": self.stress_scenario_root,
            "breach_root": self.breach_root,
            "hold_release_verdict_root": self.hold_release_verdict_root,
            "reserve_units": self.reserve_units,
            "withdrawal_queue_units": self.withdrawal_queue_units,
            "liquidity_buffer_units": self.liquidity_buffer_units,
            "fee_rebate_liability_units": self.fee_rebate_liability_units,
            "release_latency_seconds": self.release_latency_seconds,
            "stress_drawdown_bps": self.stress_drawdown_bps,
            "coverage_bps": self.coverage_bps,
            "buffer_bps": self.buffer_bps,
            "breach_count": self.breach_count,
            "hold_release_verdict": self.hold_release_verdict.as_str(),
            "gate_root": self.gate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseSloGateVerdict {
    pub gate_complete: bool,
    pub reserve_coverage_met: bool,
    pub liquidity_buffer_met: bool,
    pub fee_rebate_liabilities_covered: bool,
    pub time_to_release_slo_met: bool,
    pub stress_scenarios_passed: bool,
    pub zero_breaches: bool,
    pub release_allowed: bool,
    pub production_blocked: bool,
    pub user_escape_answer: String,
    pub production_answer: String,
    pub verdict_root: String,
}

impl ReleaseSloGateVerdict {
    pub fn new(config: &Config, counters: &Counters, records: &[ReleaseSloGateRecord]) -> Self {
        let gate_complete = counters.gate_record_count >= config.required_gate_records;
        let reserve_coverage_met = bps(
            counters.total_reserve_units,
            counters
                .total_withdrawal_queue_units
                .saturating_add(counters.total_fee_rebate_liability_units),
        ) >= config.min_release_coverage_bps;
        let liquidity_buffer_met = bps(
            counters.total_liquidity_buffer_units,
            counters.total_withdrawal_queue_units,
        ) >= config.min_buffer_bps;
        let fee_rebate_liabilities_covered = !config.require_fee_rebate_liability_coverage
            || counters.total_reserve_units
                >= counters
                    .total_withdrawal_queue_units
                    .saturating_add(counters.total_fee_rebate_liability_units);
        let time_to_release_slo_met = records
            .iter()
            .all(|record| record.release_latency_seconds <= config.max_release_latency_seconds);
        let stress_scenarios_passed = records
            .iter()
            .all(|record| record.stress_drawdown_bps <= config.max_stress_drawdown_bps);
        let zero_breaches = !config.require_zero_breach_roots || counters.breach_count == 0;
        let release_allowed = gate_complete
            && reserve_coverage_met
            && liquidity_buffer_met
            && fee_rebate_liabilities_covered
            && time_to_release_slo_met
            && stress_scenarios_passed
            && zero_breaches
            && counters.hold_required_count == 0;
        let production_blocked = !release_allowed;
        let user_escape_answer = user_escape_answer(release_allowed).to_string();
        let production_answer = production_answer(production_blocked).to_string();
        let verdict_root = verdict_root(
            config,
            counters,
            gate_complete,
            reserve_coverage_met,
            liquidity_buffer_met,
            fee_rebate_liabilities_covered,
            time_to_release_slo_met,
            stress_scenarios_passed,
            zero_breaches,
            release_allowed,
            production_blocked,
            &user_escape_answer,
            &production_answer,
        );
        Self {
            gate_complete,
            reserve_coverage_met,
            liquidity_buffer_met,
            fee_rebate_liabilities_covered,
            time_to_release_slo_met,
            stress_scenarios_passed,
            zero_breaches,
            release_allowed,
            production_blocked,
            user_escape_answer,
            production_answer,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub gate_record_root: String,
    pub reserve_proof_root: String,
    pub withdrawal_queue_root: String,
    pub liquidity_buffer_root: String,
    pub fee_rebate_liability_root: String,
    pub time_to_release_slo_root: String,
    pub stress_scenario_root: String,
    pub breach_root: String,
    pub hold_release_verdict_root: String,
    pub verdict_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub gate_records: Vec<ReleaseSloGateRecord>,
    pub roots: Roots,
    pub verdict: ReleaseSloGateVerdict,
    pub state_commitment_root: String,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        validate_config(&config)?;
        let gate_records = GateLane::ordered()
            .iter()
            .enumerate()
            .map(|(index, lane)| ReleaseSloGateRecord::devnet(&config, *lane, index as u64 + 1))
            .collect::<Vec<_>>();
        let counters = Counters::from_records(&gate_records);
        let verdict = ReleaseSloGateVerdict::new(&config, &counters, &gate_records);
        let roots = roots(&config, &counters, &gate_records, &verdict);
        let state_commitment_root = state_commitment_root(&config, &roots, &verdict);
        Ok(Self {
            config,
            counters,
            gate_records,
            roots,
            verdict,
            state_commitment_root,
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::devnet()) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_answer_vertical_slice_force_exit_package_reserve_liquidity_release_slo_gate_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "roots_root": self.roots.state_root(),
            "verdict": self.verdict.public_record(),
            "gate_records": self
                .gate_records
                .iter()
                .map(ReleaseSloGateRecord::public_record)
                .collect::<Vec<_>>(),
            "state_commitment_root": self.state_commitment_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-RESERVE-LIQUIDITY-RELEASE-SLO-GATE-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn roots(
    config: &Config,
    counters: &Counters,
    records: &[ReleaseSloGateRecord],
    verdict: &ReleaseSloGateVerdict,
) -> Roots {
    Roots {
        config_root: config.state_root(),
        counters_root: counters.state_root(),
        gate_record_root: gate_record_vector_root(records),
        reserve_proof_root: root_for_field("RESERVE-PROOFS", records, |record| {
            record.reserve_proof_root.clone()
        }),
        withdrawal_queue_root: root_for_field("WITHDRAWAL-QUEUES", records, |record| {
            record.withdrawal_queue_root.clone()
        }),
        liquidity_buffer_root: root_for_field("LIQUIDITY-BUFFERS", records, |record| {
            record.liquidity_buffer_root.clone()
        }),
        fee_rebate_liability_root: root_for_field("FEE-REBATE-LIABILITIES", records, |record| {
            record.fee_rebate_liability_root.clone()
        }),
        time_to_release_slo_root: root_for_field("TIME-TO-RELEASE-SLOS", records, |record| {
            record.time_to_release_slo_root.clone()
        }),
        stress_scenario_root: root_for_field("STRESS-SCENARIOS", records, |record| {
            record.stress_scenario_root.clone()
        }),
        breach_root: root_for_field("BREACHES", records, |record| record.breach_root.clone()),
        hold_release_verdict_root: root_for_field("HOLD-RELEASE-VERDICTS", records, |record| {
            record.hold_release_verdict_root.clone()
        }),
        verdict_root: verdict.verdict_root.clone(),
    }
}

fn gate_record_vector_root(records: &[ReleaseSloGateRecord]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-RESERVE-LIQUIDITY-RELEASE-SLO-GATE-RECORDS",
        &records
            .iter()
            .map(ReleaseSloGateRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

fn root_for_field<F>(label: &str, records: &[ReleaseSloGateRecord], field: F) -> String
where
    F: Fn(&ReleaseSloGateRecord) -> String,
{
    let entries = records
        .iter()
        .map(|record| {
            json!({
                "gate_id": record.gate_id,
                "lane": record.lane.as_str(),
                "root": field(record),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!(
            "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-RESERVE-LIQUIDITY-RELEASE-SLO-GATE-{label}"
        ),
        &entries,
    )
}

fn lane_metric_root(
    config: &Config,
    lane: GateLane,
    label: &str,
    primary_units: u64,
    secondary_units: u64,
    metric_bps: u64,
) -> String {
    record_root(
        label,
        &json!({
            "release_slo_gate_suite": &config.release_slo_gate_suite,
            "lane": lane.as_str(),
            "primary_units": primary_units,
            "secondary_units": secondary_units,
            "metric_bps": metric_bps,
        }),
    )
}

fn breach_root(
    config: &Config,
    lane: GateLane,
    coverage_bps: u64,
    buffer_bps: u64,
    release_latency_seconds: u64,
    stress_drawdown_bps: u64,
    breach_count: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-RESERVE-LIQUIDITY-RELEASE-SLO-GATE-BREACH",
        &[
            HashPart::Str(&config.release_slo_gate_suite),
            HashPart::Str(lane.as_str()),
            HashPart::U64(coverage_bps),
            HashPart::U64(buffer_bps),
            HashPart::U64(release_latency_seconds),
            HashPart::U64(stress_drawdown_bps),
            HashPart::U64(breach_count),
        ],
        32,
    )
}

fn hold_release_verdict_root(
    config: &Config,
    lane: GateLane,
    verdict: HoldReleaseVerdict,
    breach_count: u64,
    breach_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-RESERVE-LIQUIDITY-RELEASE-SLO-GATE-HOLD-RELEASE-VERDICT",
        &[
            HashPart::Str(&config.release_slo_gate_suite),
            HashPart::Str(lane.as_str()),
            HashPart::Str(verdict.as_str()),
            HashPart::U64(breach_count),
            HashPart::Str(breach_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn gate_record_root(
    config: &Config,
    lane: GateLane,
    ordinal: u64,
    reserve_proof_root: &str,
    withdrawal_queue_root: &str,
    liquidity_buffer_root: &str,
    fee_rebate_liability_root: &str,
    time_to_release_slo_root: &str,
    stress_scenario_root: &str,
    breach_root: &str,
    hold_release_verdict_root: &str,
    verdict: HoldReleaseVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-RESERVE-LIQUIDITY-RELEASE-SLO-GATE-ROW",
        &[
            HashPart::Str(&config.release_slo_gate_suite),
            HashPart::U64(ordinal),
            HashPart::Str(lane.as_str()),
            HashPart::Str(reserve_proof_root),
            HashPart::Str(withdrawal_queue_root),
            HashPart::Str(liquidity_buffer_root),
            HashPart::Str(fee_rebate_liability_root),
            HashPart::Str(time_to_release_slo_root),
            HashPart::Str(stress_scenario_root),
            HashPart::Str(breach_root),
            HashPart::Str(hold_release_verdict_root),
            HashPart::Str(verdict.as_str()),
        ],
        32,
    )
}

fn gate_id(lane: GateLane, ordinal: u64, gate_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-RESERVE-LIQUIDITY-RELEASE-SLO-GATE-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::U64(ordinal),
            HashPart::Str(gate_root),
        ],
        16,
    )
}

fn state_commitment_root(
    config: &Config,
    roots: &Roots,
    verdict: &ReleaseSloGateVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-RESERVE-LIQUIDITY-RELEASE-SLO-GATE-STATE",
        &[
            HashPart::Str(&config.state_root()),
            HashPart::Str(&roots.state_root()),
            HashPart::Str(&roots.reserve_proof_root),
            HashPart::Str(&roots.withdrawal_queue_root),
            HashPart::Str(&roots.liquidity_buffer_root),
            HashPart::Str(&roots.fee_rebate_liability_root),
            HashPart::Str(&roots.time_to_release_slo_root),
            HashPart::Str(&roots.stress_scenario_root),
            HashPart::Str(&roots.breach_root),
            HashPart::Str(&roots.hold_release_verdict_root),
            HashPart::Str(&verdict.verdict_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn verdict_root(
    config: &Config,
    counters: &Counters,
    gate_complete: bool,
    reserve_coverage_met: bool,
    liquidity_buffer_met: bool,
    fee_rebate_liabilities_covered: bool,
    time_to_release_slo_met: bool,
    stress_scenarios_passed: bool,
    zero_breaches: bool,
    release_allowed: bool,
    production_blocked: bool,
    user_escape_answer: &str,
    production_answer: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-RESERVE-LIQUIDITY-RELEASE-SLO-GATE-VERDICT",
        &[
            HashPart::Str(&config.release_slo_gate_suite),
            HashPart::Str(&counters.state_root()),
            HashPart::Str(bool_str(gate_complete)),
            HashPart::Str(bool_str(reserve_coverage_met)),
            HashPart::Str(bool_str(liquidity_buffer_met)),
            HashPart::Str(bool_str(fee_rebate_liabilities_covered)),
            HashPart::Str(bool_str(time_to_release_slo_met)),
            HashPart::Str(bool_str(stress_scenarios_passed)),
            HashPart::Str(bool_str(zero_breaches)),
            HashPart::Str(bool_str(release_allowed)),
            HashPart::Str(bool_str(production_blocked)),
            HashPart::Str(user_escape_answer),
            HashPart::Str(production_answer),
        ],
        32,
    )
}

fn reserve_units(config: &Config, lane: GateLane, withdrawal_queue_units: u64) -> u64 {
    let base = withdrawal_queue_units.saturating_add(config.reserve_unit);
    match lane {
        GateLane::StressScenario => base.saturating_add(config.reserve_unit),
        GateLane::FeeRebateLiability => base.saturating_add(config.reserve_unit / 2),
        _ => base,
    }
}

fn withdrawal_queue_units(config: &Config, lane: GateLane) -> u64 {
    match lane {
        GateLane::ReserveProof => config.reserve_unit.saturating_mul(7),
        GateLane::WithdrawalQueue => config.reserve_unit.saturating_mul(5),
        GateLane::LiquidityBuffer => config.reserve_unit.saturating_mul(4),
        GateLane::FeeRebateLiability => config.reserve_unit.saturating_mul(3),
        GateLane::TimeToReleaseSlo => config.reserve_unit.saturating_mul(2),
        GateLane::StressScenario => config.reserve_unit.saturating_mul(6),
    }
}

fn liquidity_buffer_units(config: &Config, lane: GateLane) -> u64 {
    match lane {
        GateLane::LiquidityBuffer | GateLane::StressScenario => config.reserve_unit,
        _ => config.reserve_unit.saturating_mul(2),
    }
}

fn fee_rebate_liability_units(config: &Config, lane: GateLane) -> u64 {
    match lane {
        GateLane::FeeRebateLiability => config.reserve_unit,
        GateLane::StressScenario => config.reserve_unit / 2,
        _ => config.reserve_unit / 4,
    }
}

fn release_latency_seconds(config: &Config, lane: GateLane) -> u64 {
    match lane {
        GateLane::TimeToReleaseSlo => config.max_release_latency_seconds,
        GateLane::StressScenario => config.max_release_latency_seconds.saturating_sub(60),
        _ => config.max_release_latency_seconds / 2,
    }
}

fn stress_drawdown_bps(config: &Config, lane: GateLane) -> u64 {
    match lane {
        GateLane::StressScenario => config.max_stress_drawdown_bps,
        GateLane::LiquidityBuffer => config.max_stress_drawdown_bps / 2,
        _ => config.max_stress_drawdown_bps / 4,
    }
}

fn breach_count(
    config: &Config,
    coverage_bps: u64,
    buffer_bps: u64,
    release_latency_seconds: u64,
    stress_drawdown_bps: u64,
) -> u64 {
    let mut breaches = 0_u64;
    if coverage_bps < config.min_release_coverage_bps {
        breaches += 1;
    }
    if buffer_bps < config.min_buffer_bps {
        breaches += 1;
    }
    if release_latency_seconds > config.max_release_latency_seconds {
        breaches += 1;
    }
    if config.require_hold_on_stress_breach && stress_drawdown_bps > config.max_stress_drawdown_bps
    {
        breaches += 1;
    }
    breaches
}

fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(10_000) / denominator
}

fn validate_config(config: &Config) -> Result<()> {
    ensure(
        config.chain_id == CHAIN_ID,
        "reserve liquidity release slo gate chain mismatch",
    )?;
    ensure(
        config.protocol_version == PROTOCOL_VERSION,
        "reserve liquidity release slo gate protocol mismatch",
    )?;
    ensure(
        config.schema_version == SCHEMA_VERSION,
        "reserve liquidity release slo gate schema mismatch",
    )?;
    ensure(
        config.reserve_unit > 0,
        "reserve liquidity release slo gate reserve unit is zero",
    )?;
    ensure(
        config.required_gate_records > 0,
        "reserve liquidity release slo gate requires records",
    )?;
    ensure(
        config.max_release_latency_seconds > 0,
        "reserve liquidity release slo gate requires release latency slo",
    )?;
    ensure(
        config.roots_only,
        "reserve liquidity release slo gate must remain roots-only",
    )?;
    Ok(())
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let gate_records = GateLane::ordered()
        .iter()
        .enumerate()
        .map(|(index, lane)| ReleaseSloGateRecord::devnet(&config, *lane, index as u64 + 1))
        .collect::<Vec<_>>();
    let counters = Counters::from_records(&gate_records);
    let mut verdict = ReleaseSloGateVerdict::new(&config, &counters, &gate_records);
    verdict.release_allowed = false;
    verdict.production_blocked = true;
    verdict.user_escape_answer = reason;
    verdict.production_answer =
        "hold_production_until_release_slo_gate_config_is_valid".to_string();
    verdict.verdict_root = record_root("fallback-verdict", &verdict.public_record());
    let roots = roots(&config, &counters, &gate_records, &verdict);
    let state_commitment_root = state_commitment_root(&config, &roots, &verdict);
    State {
        config,
        counters,
        gate_records,
        roots,
        verdict,
        state_commitment_root,
    }
}

fn user_escape_answer(release_allowed: bool) -> &'static str {
    if release_allowed {
        "user_escape_force_exit_release_allowed_after_reserve_liquidity_slo_gate"
    } else {
        "user_escape_force_exit_release_held_until_reserve_liquidity_slo_gate_clears"
    }
}

fn production_answer(production_blocked: bool) -> &'static str {
    if production_blocked {
        "hold_production_until_reserve_liquidity_release_slo_gate_has_no_breaches"
    } else {
        "production_release_allowed_after_reserve_liquidity_release_slo_gate"
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
