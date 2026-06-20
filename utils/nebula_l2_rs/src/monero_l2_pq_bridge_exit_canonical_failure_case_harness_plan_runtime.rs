use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalFailureCaseHarnessPlanRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_FAILURE_CASE_HARNESS_PLAN_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-failure-case-harness-plan-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_FAILURE_CASE_HARNESS_PLAN_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const HARNESS_PLAN_SUITE: &str =
    "canonical-bridge-forced-exit-heavy-gate-failure-case-harness-plan-v1";
pub const DEFAULT_MIN_MONERO_FINALITY_DEPTH: u64 = 18;
pub const DEFAULT_REORG_QUARANTINE_DEPTH: u64 = 24;
pub const DEFAULT_MAX_PQ_EPOCH_LAG: u64 = 1;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 5;
pub const DEFAULT_MIN_WATCHER_WEIGHT_BPS: u16 = 6_700;
pub const DEFAULT_MAX_RECEIPT_WITHHOLD_BLOCKS: u64 = 8;
pub const DEFAULT_MIN_SETTLEMENT_PROOF_DEPTH: u64 = 2;
pub const DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 12;
pub const DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS: u16 = 10_000;
pub const DEFAULT_MAX_PUBLIC_METADATA_FIELDS: u16 = 3;
pub const DEFAULT_FEE_CAP_BPS: u16 = 8;
pub const DEFAULT_MIN_WALLET_RECONSTRUCTION_SHARES: u64 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCaseKind {
    ShallowFinality,
    MoneroReorg,
    StalePqEpoch,
    WeakQuorum,
    ReceiptWithholding,
    InvalidSettlement,
    PrematureRelease,
    LiquidityExhaustion,
    MetadataLeak,
    FeeGrief,
    WalletReconstructionFailure,
}

impl FailureCaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShallowFinality => "shallow_finality",
            Self::MoneroReorg => "monero_reorg",
            Self::StalePqEpoch => "stale_pq_epoch",
            Self::WeakQuorum => "weak_quorum",
            Self::ReceiptWithholding => "receipt_withholding",
            Self::InvalidSettlement => "invalid_settlement",
            Self::PrematureRelease => "premature_release",
            Self::LiquidityExhaustion => "liquidity_exhaustion",
            Self::MetadataLeak => "metadata_leak",
            Self::FeeGrief => "fee_grief",
            Self::WalletReconstructionFailure => "wallet_reconstruction_failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedResponse {
    RejectBeforeHeavyGatePass,
    QuarantineAndRejectBeforeHeavyGatePass,
    RejectReleaseAndOpenAuditLane,
}

impl FailClosedResponse {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RejectBeforeHeavyGatePass => "reject_before_heavy_gate_pass",
            Self::QuarantineAndRejectBeforeHeavyGatePass => {
                "quarantine_and_reject_before_heavy_gate_pass"
            }
            Self::RejectReleaseAndOpenAuditLane => "reject_release_and_open_audit_lane",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub harness_plan_suite: String,
    pub min_monero_finality_depth: u64,
    pub reorg_quarantine_depth: u64,
    pub max_pq_epoch_lag: u64,
    pub min_watcher_quorum: u64,
    pub min_watcher_weight_bps: u16,
    pub max_receipt_withhold_blocks: u64,
    pub min_settlement_proof_depth: u64,
    pub release_delay_blocks: u64,
    pub min_liquidity_coverage_bps: u16,
    pub max_public_metadata_fields: u16,
    pub fee_cap_bps: u16,
    pub min_wallet_reconstruction_shares: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            harness_plan_suite: HARNESS_PLAN_SUITE.to_string(),
            min_monero_finality_depth: DEFAULT_MIN_MONERO_FINALITY_DEPTH,
            reorg_quarantine_depth: DEFAULT_REORG_QUARANTINE_DEPTH,
            max_pq_epoch_lag: DEFAULT_MAX_PQ_EPOCH_LAG,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            min_watcher_weight_bps: DEFAULT_MIN_WATCHER_WEIGHT_BPS,
            max_receipt_withhold_blocks: DEFAULT_MAX_RECEIPT_WITHHOLD_BLOCKS,
            min_settlement_proof_depth: DEFAULT_MIN_SETTLEMENT_PROOF_DEPTH,
            release_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            min_liquidity_coverage_bps: DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS,
            max_public_metadata_fields: DEFAULT_MAX_PUBLIC_METADATA_FIELDS,
            fee_cap_bps: DEFAULT_FEE_CAP_BPS,
            min_wallet_reconstruction_shares: DEFAULT_MIN_WALLET_RECONSTRUCTION_SHARES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "harness_plan_suite": self.harness_plan_suite,
            "min_monero_finality_depth": self.min_monero_finality_depth,
            "reorg_quarantine_depth": self.reorg_quarantine_depth,
            "max_pq_epoch_lag": self.max_pq_epoch_lag,
            "min_watcher_quorum": self.min_watcher_quorum,
            "min_watcher_weight_bps": self.min_watcher_weight_bps,
            "max_receipt_withhold_blocks": self.max_receipt_withhold_blocks,
            "min_settlement_proof_depth": self.min_settlement_proof_depth,
            "release_delay_blocks": self.release_delay_blocks,
            "min_liquidity_coverage_bps": self.min_liquidity_coverage_bps,
            "max_public_metadata_fields": self.max_public_metadata_fields,
            "fee_cap_bps": self.fee_cap_bps,
            "min_wallet_reconstruction_shares": self.min_wallet_reconstruction_shares,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailureCase {
    pub case_id: String,
    pub kind: FailureCaseKind,
    pub planned_order: u64,
    pub l2_height: u64,
    pub monero_depth: u64,
    pub reorg_depth: u64,
    pub pq_epoch: u64,
    pub canonical_pq_epoch: u64,
    pub watcher_quorum: u64,
    pub watcher_weight_bps: u16,
    pub receipt_withhold_blocks: u64,
    pub settlement_proof_depth: u64,
    pub release_delay_blocks: u64,
    pub liquidity_coverage_bps: u16,
    pub public_metadata_fields: u16,
    pub fee_bps: u16,
    pub wallet_reconstruction_shares: u64,
    pub adversarial_condition_root: String,
    pub expected_response: FailClosedResponse,
    pub reject_before_heavy_gate_pass: bool,
    pub expected_operator_action: String,
    pub answer: String,
}

impl FailureCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "kind": self.kind.as_str(),
            "planned_order": self.planned_order,
            "l2_height": self.l2_height,
            "monero_depth": self.monero_depth,
            "reorg_depth": self.reorg_depth,
            "pq_epoch": self.pq_epoch,
            "canonical_pq_epoch": self.canonical_pq_epoch,
            "watcher_quorum": self.watcher_quorum,
            "watcher_weight_bps": self.watcher_weight_bps,
            "receipt_withhold_blocks": self.receipt_withhold_blocks,
            "settlement_proof_depth": self.settlement_proof_depth,
            "release_delay_blocks": self.release_delay_blocks,
            "liquidity_coverage_bps": self.liquidity_coverage_bps,
            "public_metadata_fields": self.public_metadata_fields,
            "fee_bps": self.fee_bps,
            "wallet_reconstruction_shares": self.wallet_reconstruction_shares,
            "adversarial_condition_root": self.adversarial_condition_root,
            "expected_response": self.expected_response.as_str(),
            "reject_before_heavy_gate_pass": self.reject_before_heavy_gate_pass,
            "expected_operator_action": self.expected_operator_action,
            "answer": self.answer,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("failure_case", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub cases: Vec<FailureCase>,
    pub reject_before_heavy_gate_pass_case_ids: Vec<String>,
    pub reject_before_heavy_gate_pass_cases: u64,
    pub audit_lane_cases: u64,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let cases = devnet_cases(&config);
        let reject_before_heavy_gate_pass_case_ids = cases
            .iter()
            .filter(|case| case.reject_before_heavy_gate_pass)
            .map(|case| case.case_id.clone())
            .collect::<Vec<_>>();
        let reject_before_heavy_gate_pass_cases =
            reject_before_heavy_gate_pass_case_ids.len() as u64;
        let audit_lane_cases = cases
            .iter()
            .filter(|case| {
                case.expected_response == FailClosedResponse::RejectReleaseAndOpenAuditLane
            })
            .count() as u64;

        Self {
            config,
            cases,
            reject_before_heavy_gate_pass_case_ids,
            reject_before_heavy_gate_pass_cases,
            audit_lane_cases,
        }
    }

    pub fn public_record(&self) -> Value {
        let case_records: Vec<Value> = self.cases.iter().map(FailureCase::public_record).collect();
        json!({
            "config": self.config.public_record(),
            "cases": case_records,
            "case_root": self.case_root(),
            "reject_before_heavy_gate_pass_case_ids": self.reject_before_heavy_gate_pass_case_ids,
            "reject_before_heavy_gate_pass_cases": self.reject_before_heavy_gate_pass_cases,
            "audit_lane_cases": self.audit_lane_cases,
        })
    }

    pub fn case_root(&self) -> String {
        let records: Vec<Value> = self.cases.iter().map(FailureCase::public_record).collect();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-FAILURE-CASE-HARNESS-PLAN-CASE",
            &records,
        )
    }

    pub fn state_root(&self) -> String {
        let reject_records: Vec<Value> = self
            .reject_before_heavy_gate_pass_case_ids
            .iter()
            .map(|case_id| json!({ "case_id": case_id }))
            .collect();
        let reject_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-FAILURE-CASE-HARNESS-PLAN-REJECT",
            &reject_records,
        );
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-FAILURE-CASE-HARNESS-PLAN-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.case_root()),
                HashPart::Str(&reject_root),
                HashPart::U64(self.reject_before_heavy_gate_pass_cases),
                HashPart::U64(self.audit_lane_cases),
            ],
            32,
        )
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
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

pub fn devnet_cases(config: &Config) -> Vec<FailureCase> {
    let base_height = 2_404_800;
    let canonical_pq_epoch = 144;
    vec![
        failure_case(
            config,
            FailureCaseKind::ShallowFinality,
            1,
            base_height,
            config.min_monero_finality_depth - 6,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            config.min_watcher_quorum,
            8_100,
            0,
            config.min_settlement_proof_depth,
            config.release_delay_blocks,
            11_200,
            2,
            4,
            config.min_wallet_reconstruction_shares,
        ),
        failure_case(
            config,
            FailureCaseKind::MoneroReorg,
            2,
            base_height + 12,
            config.min_monero_finality_depth + 4,
            config.reorg_quarantine_depth + 3,
            canonical_pq_epoch,
            canonical_pq_epoch,
            config.min_watcher_quorum,
            8_100,
            0,
            config.min_settlement_proof_depth,
            config.release_delay_blocks,
            11_200,
            2,
            4,
            config.min_wallet_reconstruction_shares,
        ),
        failure_case(
            config,
            FailureCaseKind::StalePqEpoch,
            3,
            base_height + 24,
            config.min_monero_finality_depth + 2,
            0,
            canonical_pq_epoch - config.max_pq_epoch_lag - 2,
            canonical_pq_epoch,
            config.min_watcher_quorum,
            8_100,
            0,
            config.min_settlement_proof_depth,
            config.release_delay_blocks,
            11_400,
            2,
            4,
            config.min_wallet_reconstruction_shares,
        ),
        failure_case(
            config,
            FailureCaseKind::WeakQuorum,
            4,
            base_height + 36,
            config.min_monero_finality_depth + 2,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            config.min_watcher_quorum - 2,
            config.min_watcher_weight_bps - 900,
            0,
            config.min_settlement_proof_depth,
            config.release_delay_blocks,
            11_400,
            2,
            4,
            config.min_wallet_reconstruction_shares,
        ),
        failure_case(
            config,
            FailureCaseKind::ReceiptWithholding,
            5,
            base_height + 48,
            config.min_monero_finality_depth + 2,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            config.min_watcher_quorum,
            8_100,
            config.max_receipt_withhold_blocks + 5,
            config.min_settlement_proof_depth,
            config.release_delay_blocks,
            11_200,
            2,
            4,
            config.min_wallet_reconstruction_shares,
        ),
        failure_case(
            config,
            FailureCaseKind::InvalidSettlement,
            6,
            base_height + 60,
            config.min_monero_finality_depth + 2,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            config.min_watcher_quorum,
            8_100,
            0,
            config.min_settlement_proof_depth - 1,
            config.release_delay_blocks,
            11_200,
            2,
            4,
            config.min_wallet_reconstruction_shares,
        ),
        failure_case(
            config,
            FailureCaseKind::PrematureRelease,
            7,
            base_height + 72,
            config.min_monero_finality_depth + 2,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            config.min_watcher_quorum,
            8_100,
            0,
            config.min_settlement_proof_depth,
            config.release_delay_blocks - 5,
            11_200,
            2,
            4,
            config.min_wallet_reconstruction_shares,
        ),
        failure_case(
            config,
            FailureCaseKind::LiquidityExhaustion,
            8,
            base_height + 84,
            config.min_monero_finality_depth + 2,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            config.min_watcher_quorum,
            8_100,
            0,
            config.min_settlement_proof_depth,
            config.release_delay_blocks,
            config.min_liquidity_coverage_bps - 1_900,
            2,
            4,
            config.min_wallet_reconstruction_shares,
        ),
        failure_case(
            config,
            FailureCaseKind::MetadataLeak,
            9,
            base_height + 96,
            config.min_monero_finality_depth + 2,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            config.min_watcher_quorum,
            8_100,
            0,
            config.min_settlement_proof_depth,
            config.release_delay_blocks,
            11_200,
            config.max_public_metadata_fields + 4,
            4,
            config.min_wallet_reconstruction_shares,
        ),
        failure_case(
            config,
            FailureCaseKind::FeeGrief,
            10,
            base_height + 108,
            config.min_monero_finality_depth + 2,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            config.min_watcher_quorum,
            8_100,
            0,
            config.min_settlement_proof_depth,
            config.release_delay_blocks,
            11_200,
            2,
            config.fee_cap_bps + 34,
            config.min_wallet_reconstruction_shares,
        ),
        failure_case(
            config,
            FailureCaseKind::WalletReconstructionFailure,
            11,
            base_height + 120,
            config.min_monero_finality_depth + 2,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            config.min_watcher_quorum,
            8_100,
            0,
            config.min_settlement_proof_depth,
            config.release_delay_blocks,
            11_200,
            2,
            4,
            config.min_wallet_reconstruction_shares - 1,
        ),
    ]
}

pub fn failure_case(
    config: &Config,
    kind: FailureCaseKind,
    planned_order: u64,
    l2_height: u64,
    monero_depth: u64,
    reorg_depth: u64,
    pq_epoch: u64,
    canonical_pq_epoch: u64,
    watcher_quorum: u64,
    watcher_weight_bps: u16,
    receipt_withhold_blocks: u64,
    settlement_proof_depth: u64,
    release_delay_blocks: u64,
    liquidity_coverage_bps: u16,
    public_metadata_fields: u16,
    fee_bps: u16,
    wallet_reconstruction_shares: u64,
) -> FailureCase {
    let adversarial_condition_root = condition_root(kind, planned_order, l2_height);
    let expected_response = expected_response_for(
        config,
        kind,
        monero_depth,
        reorg_depth,
        pq_epoch,
        canonical_pq_epoch,
        watcher_quorum,
        watcher_weight_bps,
        receipt_withhold_blocks,
        settlement_proof_depth,
        release_delay_blocks,
        liquidity_coverage_bps,
        public_metadata_fields,
        fee_bps,
        wallet_reconstruction_shares,
    );
    let reject_before_heavy_gate_pass =
        expected_response != FailClosedResponse::RejectReleaseAndOpenAuditLane;
    let expected_operator_action = operator_action(expected_response);
    let case_id = case_id(kind, planned_order, &adversarial_condition_root);
    let answer = failure_answer(kind, expected_response, reject_before_heavy_gate_pass);

    FailureCase {
        case_id,
        kind,
        planned_order,
        l2_height,
        monero_depth,
        reorg_depth,
        pq_epoch,
        canonical_pq_epoch,
        watcher_quorum,
        watcher_weight_bps,
        receipt_withhold_blocks,
        settlement_proof_depth,
        release_delay_blocks,
        liquidity_coverage_bps,
        public_metadata_fields,
        fee_bps,
        wallet_reconstruction_shares,
        adversarial_condition_root,
        expected_response,
        reject_before_heavy_gate_pass,
        expected_operator_action,
        answer,
    }
}

pub fn expected_response_for(
    config: &Config,
    kind: FailureCaseKind,
    monero_depth: u64,
    reorg_depth: u64,
    pq_epoch: u64,
    canonical_pq_epoch: u64,
    watcher_quorum: u64,
    watcher_weight_bps: u16,
    receipt_withhold_blocks: u64,
    settlement_proof_depth: u64,
    release_delay_blocks: u64,
    liquidity_coverage_bps: u16,
    public_metadata_fields: u16,
    fee_bps: u16,
    wallet_reconstruction_shares: u64,
) -> FailClosedResponse {
    if matches!(kind, FailureCaseKind::MoneroReorg) || reorg_depth >= config.reorg_quarantine_depth
    {
        return FailClosedResponse::QuarantineAndRejectBeforeHeavyGatePass;
    }

    let epoch_lag = canonical_pq_epoch.saturating_sub(pq_epoch);
    let reject_before_heavy_gate = monero_depth < config.min_monero_finality_depth
        || epoch_lag > config.max_pq_epoch_lag
        || watcher_quorum < config.min_watcher_quorum
        || watcher_weight_bps < config.min_watcher_weight_bps
        || receipt_withhold_blocks > config.max_receipt_withhold_blocks
        || settlement_proof_depth < config.min_settlement_proof_depth
        || release_delay_blocks < config.release_delay_blocks
        || liquidity_coverage_bps < config.min_liquidity_coverage_bps
        || public_metadata_fields > config.max_public_metadata_fields
        || fee_bps > config.fee_cap_bps
        || wallet_reconstruction_shares < config.min_wallet_reconstruction_shares
        || matches!(
            kind,
            FailureCaseKind::ShallowFinality
                | FailureCaseKind::StalePqEpoch
                | FailureCaseKind::WeakQuorum
                | FailureCaseKind::ReceiptWithholding
                | FailureCaseKind::InvalidSettlement
                | FailureCaseKind::PrematureRelease
                | FailureCaseKind::LiquidityExhaustion
                | FailureCaseKind::MetadataLeak
                | FailureCaseKind::FeeGrief
                | FailureCaseKind::WalletReconstructionFailure
        );

    if reject_before_heavy_gate {
        FailClosedResponse::RejectBeforeHeavyGatePass
    } else {
        FailClosedResponse::RejectReleaseAndOpenAuditLane
    }
}

pub fn operator_action(response: FailClosedResponse) -> String {
    match response {
        FailClosedResponse::RejectBeforeHeavyGatePass => {
            "halt heavy-gate scheduling, retain escrow lock, and persist rejection evidence"
        }
        FailClosedResponse::QuarantineAndRejectBeforeHeavyGatePass => {
            "quarantine bridge lane, halt heavy-gate scheduling, and require fresh Monero finality"
        }
        FailClosedResponse::RejectReleaseAndOpenAuditLane => {
            "reject release and route the transcript to an audit lane"
        }
    }
    .to_string()
}

pub fn failure_answer(
    kind: FailureCaseKind,
    response: FailClosedResponse,
    reject_before_heavy_gate_pass: bool,
) -> String {
    let gate_answer = if reject_before_heavy_gate_pass {
        "yes"
    } else {
        "no"
    };
    format!(
        "{gate_answer}: {} must map to {} for the canonical bridge forced-exit heavy gate",
        kind.as_str(),
        response.as_str()
    )
}

pub fn case_id(
    kind: FailureCaseKind,
    planned_order: u64,
    adversarial_condition_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-FAILURE-CASE-HARNESS-PLAN-CASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::U64(planned_order),
            HashPart::Str(adversarial_condition_root),
        ],
        32,
    )
}

pub fn condition_root(kind: FailureCaseKind, planned_order: u64, l2_height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-FAILURE-CASE-HARNESS-PLAN-CONDITION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::U64(planned_order),
            HashPart::U64(l2_height),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-FAILURE-CASE-HARNESS-PLAN-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
