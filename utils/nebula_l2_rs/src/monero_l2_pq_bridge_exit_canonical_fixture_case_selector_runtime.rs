use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqBridgeExitCanonicalFixtureCaseSelectorRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-fixture-case-selector-runtime-v1";
pub const SCHEMA_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-fixture-case-selector-public-record-v1";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";

const DEVNET_HEIGHT: u64 = 42_720;
const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
const DEVNET_L2_NETWORK: &str = "nebula-devnet";
const DEVNET_ASSET_ID: &str = "wxmr-devnet";
const DEVNET_MIN_PQ_SECURITY_BITS: u64 = 256;
const DEVNET_MIN_PRIVACY_SET_SIZE: u64 = 128;
const DEVNET_MAX_DISCLOSURE_UNITS: u64 = 8;
const DEVNET_MIN_RESERVE_COVERAGE_BPS: u64 = 10_250;
const DEVNET_HEAVY_GATE_LABEL: &str = "bridge-forced-exit-heavy-gate";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureLane {
    Deposit,
    PrivateState,
    Settlement,
    Challenge,
    Pq,
    Privacy,
    Reserve,
    Wallet,
    OperatorFailure,
}

impl FixtureLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::PrivateState => "private_state",
            Self::Settlement => "settlement",
            Self::Challenge => "challenge",
            Self::Pq => "pq",
            Self::Privacy => "privacy",
            Self::Reserve => "reserve",
            Self::Wallet => "wallet",
            Self::OperatorFailure => "operator_failure",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionPriority {
    Critical,
    Required,
    Adversarial,
    Coverage,
    Optional,
}

impl SelectionPriority {
    pub fn rank(self) -> u64 {
        match self {
            Self::Critical => 0,
            Self::Required => 1,
            Self::Adversarial => 2,
            Self::Coverage => 3,
            Self::Optional => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Required => "required",
            Self::Adversarial => "adversarial",
            Self::Coverage => "coverage",
            Self::Optional => "optional",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    Pass,
    Reject,
}

impl ExpectedOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeavyGateVerdict {
    Include,
    Exclude,
}

impl HeavyGateVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Exclude => "exclude",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub gate_label: String,
    pub runtime_gates_allowed: bool,
    pub cargo_gates_allowed: bool,
    pub min_pq_security_bits: u64,
    pub min_privacy_set_size: u64,
    pub max_disclosure_units: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_selected_cases: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceRoots {
    pub deposit_root: String,
    pub private_state_root: String,
    pub settlement_root: String,
    pub challenge_root: String,
    pub pq_attestation_root: String,
    pub privacy_budget_root: String,
    pub reserve_root: String,
    pub wallet_root: String,
    pub operator_failure_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyBudget {
    pub min_anonymity_set_size: u64,
    pub max_disclosure_units: u64,
    pub expected_disclosure_units: u64,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqRequirements {
    pub scheme: String,
    pub min_security_bits: u64,
    pub requires_hybrid_signature: bool,
    pub requires_replay_bound_transcript: bool,
    pub requires_operator_key_rotation: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveCoverage {
    pub liability_piconero: u64,
    pub reserve_piconero: u64,
    pub coverage_bps: u64,
    pub min_coverage_bps: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FixtureCase {
    pub case_id: String,
    pub lane: FixtureLane,
    pub priority: SelectionPriority,
    pub title: String,
    pub path_stage: String,
    pub expected_outcome: ExpectedOutcome,
    pub evidence_roots: EvidenceRoots,
    pub privacy_budget: PrivacyBudget,
    pub pq_requirements: PqRequirements,
    pub reserve_coverage: ReserveCoverage,
    pub adversarial_reason: String,
    pub inclusion_verdict: HeavyGateVerdict,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectionSummary {
    pub selected_case_count: u64,
    pub pass_case_count: u64,
    pub reject_case_count: u64,
    pub included_lane_root: String,
    pub required_evidence_root: String,
    pub gate_inclusion_verdict: HeavyGateVerdict,
    pub gate_reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub config: Config,
    pub cases: Vec<FixtureCase>,
    pub summary: SelectionSummary,
}

impl State {
    pub fn public_record(&self) -> Value {
        let case_records = self
            .cases
            .iter()
            .map(FixtureCase::public_record)
            .collect::<Vec<_>>();
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "chain_id": self.config.chain_id,
            "config": self.config.public_record(),
            "cases": case_records,
            "summary": {
                "selected_case_count": self.summary.selected_case_count,
                "pass_case_count": self.summary.pass_case_count,
                "reject_case_count": self.summary.reject_case_count,
                "included_lane_root": self.summary.included_lane_root,
                "required_evidence_root": self.summary.required_evidence_root,
                "gate_inclusion_verdict": self.summary.gate_inclusion_verdict.as_str(),
                "gate_reason": self.summary.gate_reason,
            },
            "case_root": merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-CASES", &case_records),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-FIXTURE-CASE-SELECTOR-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "gate_label": self.gate_label,
            "runtime_gates_allowed": self.runtime_gates_allowed,
            "cargo_gates_allowed": self.cargo_gates_allowed,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_disclosure_units": self.max_disclosure_units,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_selected_cases": self.max_selected_cases,
        })
    }
}

impl FixtureCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "lane": self.lane.as_str(),
            "priority": self.priority.as_str(),
            "priority_rank": self.priority.rank(),
            "title": self.title,
            "path_stage": self.path_stage,
            "expected_outcome": self.expected_outcome.as_str(),
            "evidence_roots": self.evidence_roots,
            "privacy_budget": self.privacy_budget,
            "pq_requirements": self.pq_requirements,
            "reserve_coverage": self.reserve_coverage,
            "adversarial_reason": self.adversarial_reason,
            "inclusion_verdict": self.inclusion_verdict.as_str(),
        })
    }
}

pub fn devnet() -> State {
    let config = Config {
        chain_id: CHAIN_ID.to_string(),
        monero_network: DEVNET_MONERO_NETWORK.to_string(),
        l2_network: DEVNET_L2_NETWORK.to_string(),
        asset_id: DEVNET_ASSET_ID.to_string(),
        gate_label: DEVNET_HEAVY_GATE_LABEL.to_string(),
        runtime_gates_allowed: true,
        cargo_gates_allowed: true,
        min_pq_security_bits: DEVNET_MIN_PQ_SECURITY_BITS,
        min_privacy_set_size: DEVNET_MIN_PRIVACY_SET_SIZE,
        max_disclosure_units: DEVNET_MAX_DISCLOSURE_UNITS,
        min_reserve_coverage_bps: DEVNET_MIN_RESERVE_COVERAGE_BPS,
        max_selected_cases: 9,
    };
    let cases = canonical_devnet_cases(&config);
    let summary = summarize_selection(&config, &cases);

    State {
        protocol_version: PROTOCOL_VERSION.to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        hash_suite: HASH_SUITE.to_string(),
        config,
        cases,
        summary,
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn canonical_devnet_cases(config: &Config) -> Vec<FixtureCase> {
    vec![
        fixture_case(
            config,
            FixtureLane::Deposit,
            SelectionPriority::Critical,
            "devnet-deposit-anchor-matured",
            "get_in",
            ExpectedOutcome::Pass,
            "deposit with mature Monero confirmation depth and spendable L2 mint note",
            192,
            2,
            256,
            12_400_000_000,
            11_900_000_000,
        ),
        fixture_case(
            config,
            FixtureLane::PrivateState,
            SelectionPriority::Critical,
            "devnet-private-note-nullifier-move",
            "move_private",
            ExpectedOutcome::Pass,
            "private transfer consumes the deposit note and preserves nullifier uniqueness",
            160,
            3,
            256,
            11_700_000_000,
            11_100_000_000,
        ),
        fixture_case(
            config,
            FixtureLane::Settlement,
            SelectionPriority::Required,
            "devnet-force-exit-settlement-release",
            "force_out",
            ExpectedOutcome::Pass,
            "forced exit batch settles after challenge window with deterministic recipient commitment",
            160,
            3,
            256,
            11_100_000_000,
            10_700_000_000,
        ),
        fixture_case(
            config,
            FixtureLane::Challenge,
            SelectionPriority::Adversarial,
            "devnet-duplicate-nullifier-challenge",
            "force_out",
            ExpectedOutcome::Reject,
            "challenge evidence rejects a second exit using the moved private note nullifier",
            160,
            4,
            256,
            11_100_000_000,
            10_700_000_000,
        ),
        fixture_case(
            config,
            FixtureLane::Pq,
            SelectionPriority::Adversarial,
            "devnet-stale-pq-transcript-replay",
            "force_out",
            ExpectedOutcome::Reject,
            "replayed post-quantum transcript is not bound to the forced-exit batch root",
            144,
            4,
            192,
            10_900_000_000,
            10_500_000_000,
        ),
        fixture_case(
            config,
            FixtureLane::Privacy,
            SelectionPriority::Required,
            "devnet-privacy-budget-boundary",
            "move_private",
            ExpectedOutcome::Reject,
            "privacy budget rejects a disclosure set that exceeds the canonical heavy-gate ceiling",
            96,
            12,
            256,
            10_800_000_000,
            10_500_000_000,
        ),
        fixture_case(
            config,
            FixtureLane::Reserve,
            SelectionPriority::Required,
            "devnet-reserve-coverage-underflow",
            "force_out",
            ExpectedOutcome::Reject,
            "reserve proof rejects release when attested reserve falls below liabilities",
            160,
            4,
            256,
            10_900_000_000,
            10_100_000_000,
        ),
        fixture_case(
            config,
            FixtureLane::Wallet,
            SelectionPriority::Coverage,
            "devnet-wallet-view-tag-mismatch",
            "get_in",
            ExpectedOutcome::Reject,
            "wallet fixture rejects a deposit scan result with mismatched view tag binding",
            144,
            4,
            256,
            10_700_000_000,
            10_400_000_000,
        ),
        fixture_case(
            config,
            FixtureLane::OperatorFailure,
            SelectionPriority::Adversarial,
            "devnet-operator-withheld-settlement-proof",
            "force_out",
            ExpectedOutcome::Reject,
            "operator failure path requires watchtower evidence when settlement proof is withheld",
            160,
            5,
            256,
            10_600_000_000,
            10_300_000_000,
        ),
    ]
}

fn summarize_selection(config: &Config, cases: &[FixtureCase]) -> SelectionSummary {
    let included = cases
        .iter()
        .filter(|case| case.inclusion_verdict == HeavyGateVerdict::Include)
        .collect::<Vec<_>>();
    let lane_records = included
        .iter()
        .map(|case| {
            json!({
                "case_id": case.case_id,
                "lane": case.lane.as_str(),
                "priority_rank": case.priority.rank(),
                "expected_outcome": case.expected_outcome.as_str(),
            })
        })
        .collect::<Vec<_>>();
    let evidence_records = included
        .iter()
        .map(|case| serde_json::to_value(&case.evidence_roots).unwrap_or(Value::Null))
        .collect::<Vec<_>>();
    let pass_case_count = included
        .iter()
        .filter(|case| case.expected_outcome == ExpectedOutcome::Pass)
        .count() as u64;
    let reject_case_count = included.len() as u64 - pass_case_count;
    let gate_inclusion_verdict = if config.runtime_gates_allowed && config.cargo_gates_allowed {
        HeavyGateVerdict::Include
    } else {
        HeavyGateVerdict::Exclude
    };

    SelectionSummary {
        selected_case_count: included.len() as u64,
        pass_case_count,
        reject_case_count,
        included_lane_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-INCLUDED-LANES",
            &lane_records,
        ),
        required_evidence_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-REQUIRED-EVIDENCE",
            &evidence_records,
        ),
        gate_inclusion_verdict,
        gate_reason: "runtime and cargo gates are allowed, so the minimal adversarial get-in move-private force-out set is selected".to_string(),
    }
}

fn fixture_case(
    config: &Config,
    lane: FixtureLane,
    priority: SelectionPriority,
    label: &str,
    path_stage: &str,
    expected_outcome: ExpectedOutcome,
    adversarial_reason: &str,
    anonymity_set_size: u64,
    disclosure_units: u64,
    pq_security_bits: u64,
    liability_piconero: u64,
    reserve_piconero: u64,
) -> FixtureCase {
    let case_id = fixture_case_id(label, lane, path_stage, expected_outcome);
    let evidence_roots = evidence_roots(&case_id, lane, path_stage);
    let privacy_budget = PrivacyBudget {
        min_anonymity_set_size: anonymity_set_size,
        max_disclosure_units: config.max_disclosure_units,
        expected_disclosure_units: disclosure_units,
        note: privacy_note(anonymity_set_size, disclosure_units, config),
    };
    let pq_requirements = PqRequirements {
        scheme: "ml-dsa-87-ed25519-hybrid-devnet".to_string(),
        min_security_bits: pq_security_bits,
        requires_hybrid_signature: true,
        requires_replay_bound_transcript: true,
        requires_operator_key_rotation: lane == FixtureLane::OperatorFailure,
    };
    let reserve_coverage = ReserveCoverage {
        liability_piconero,
        reserve_piconero,
        coverage_bps: reserve_coverage_bps(reserve_piconero, liability_piconero),
        min_coverage_bps: config.min_reserve_coverage_bps,
    };
    let inclusion_verdict =
        case_inclusion_verdict(config, &privacy_budget, &pq_requirements, &reserve_coverage);

    FixtureCase {
        case_id,
        lane,
        priority,
        title: label.replace('-', " "),
        path_stage: path_stage.to_string(),
        expected_outcome,
        evidence_roots,
        privacy_budget,
        pq_requirements,
        reserve_coverage,
        adversarial_reason: adversarial_reason.to_string(),
        inclusion_verdict,
    }
}

fn case_inclusion_verdict(
    config: &Config,
    privacy_budget: &PrivacyBudget,
    pq_requirements: &PqRequirements,
    reserve_coverage: &ReserveCoverage,
) -> HeavyGateVerdict {
    let gate_open = config.runtime_gates_allowed && config.cargo_gates_allowed;
    let privacy_relevant = privacy_budget.min_anonymity_set_size >= config.min_privacy_set_size
        || privacy_budget.expected_disclosure_units > config.max_disclosure_units;
    let pq_relevant = pq_requirements.min_security_bits >= config.min_pq_security_bits
        || pq_requirements.min_security_bits < config.min_pq_security_bits;
    let reserve_relevant = reserve_coverage.coverage_bps >= config.min_reserve_coverage_bps
        || reserve_coverage.coverage_bps < config.min_reserve_coverage_bps;

    if gate_open && privacy_relevant && pq_relevant && reserve_relevant {
        HeavyGateVerdict::Include
    } else {
        HeavyGateVerdict::Exclude
    }
}

fn evidence_roots(case_id: &str, lane: FixtureLane, path_stage: &str) -> EvidenceRoots {
    EvidenceRoots {
        deposit_root: evidence_root(case_id, lane, path_stage, "deposit"),
        private_state_root: evidence_root(case_id, lane, path_stage, "private-state"),
        settlement_root: evidence_root(case_id, lane, path_stage, "settlement"),
        challenge_root: evidence_root(case_id, lane, path_stage, "challenge"),
        pq_attestation_root: evidence_root(case_id, lane, path_stage, "pq-attestation"),
        privacy_budget_root: evidence_root(case_id, lane, path_stage, "privacy-budget"),
        reserve_root: evidence_root(case_id, lane, path_stage, "reserve"),
        wallet_root: evidence_root(case_id, lane, path_stage, "wallet"),
        operator_failure_root: evidence_root(case_id, lane, path_stage, "operator-failure"),
    }
}

fn fixture_case_id(
    label: &str,
    lane: FixtureLane,
    path_stage: &str,
    expected_outcome: ExpectedOutcome,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-CASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(lane.as_str()),
            HashPart::Str(path_stage),
            HashPart::Str(expected_outcome.as_str()),
            HashPart::U64(DEVNET_HEIGHT),
        ],
        32,
    )
}

fn evidence_root(
    case_id: &str,
    lane: FixtureLane,
    path_stage: &str,
    evidence_kind: &str,
) -> String {
    let leaf = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "case_id": case_id,
        "lane": lane.as_str(),
        "path_stage": path_stage,
        "evidence_kind": evidence_kind,
        "height": DEVNET_HEIGHT,
    });
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-EVIDENCE",
        &[leaf, json!(evidence_kind)],
    )
}

fn privacy_note(anonymity_set_size: u64, disclosure_units: u64, config: &Config) -> String {
    let anonymity_status = if anonymity_set_size >= config.min_privacy_set_size {
        "anonymity-set-covered"
    } else {
        "anonymity-set-boundary"
    };
    let disclosure_status = if disclosure_units <= config.max_disclosure_units {
        "disclosure-budget-covered"
    } else {
        "disclosure-budget-exceeded"
    };
    format!("{anonymity_status}:{disclosure_status}")
}

fn reserve_coverage_bps(reserve_piconero: u64, liability_piconero: u64) -> u64 {
    if liability_piconero == 0 {
        return 0;
    }
    reserve_piconero.saturating_mul(10_000) / liability_piconero
}
