use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceLiquiditySettlementReleaseVerificationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_LIQUIDITY_SETTLEMENT_RELEASE_VERIFICATION_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-liquidity-settlement-release-verification-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_LIQUIDITY_SETTLEMENT_RELEASE_VERIFICATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str =
    "2026-06-19.forced-exit.liquidity-settlement-release-verification.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-liquidity-settlement-release-verification-runtime";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub reserve_freshness_window_blocks: u64,
    pub max_release_fee_bps: u64,
    pub watcher_quorum_threshold: u64,
    pub queue_priority_ceiling: u64,
    pub allow_partial_fill: bool,
    pub require_backstop_for_shortfall: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            reserve_freshness_window_blocks: 18,
            max_release_fee_bps: 45,
            watcher_quorum_threshold: 5,
            queue_priority_ceiling: 64,
            allow_partial_fill: true,
            require_backstop_for_shortfall: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "reserve_freshness_window_blocks": self.reserve_freshness_window_blocks,
            "max_release_fee_bps": self.max_release_fee_bps,
            "watcher_quorum_threshold": self.watcher_quorum_threshold,
            "queue_priority_ceiling": self.queue_priority_ceiling,
            "allow_partial_fill": self.allow_partial_fill,
            "require_backstop_for_shortfall": self.require_backstop_for_shortfall,
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    ReserveCoverageRoot,
    SettlementReceiptRoot,
    BackstopPoolRoot,
    FeeCapRoot,
    ShortfallAmount,
    PartialFillPolicy,
    QueuePriority,
    WatcherQuorum,
    ReserveFreshness,
    FinalUserReleaseVerdict,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveCoverageRoot => "reserve_coverage_root",
            Self::SettlementReceiptRoot => "settlement_receipt_root",
            Self::BackstopPoolRoot => "backstop_pool_root",
            Self::FeeCapRoot => "fee_cap_root",
            Self::ShortfallAmount => "shortfall_amount",
            Self::PartialFillPolicy => "partial_fill_policy",
            Self::QueuePriority => "queue_priority",
            Self::WatcherQuorum => "watcher_quorum",
            Self::ReserveFreshness => "reserve_freshness",
            Self::FinalUserReleaseVerdict => "final_user_release_verdict",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseVerdict {
    ReleaseUserFunds,
    FailClosed,
}

impl ReleaseVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseUserFunds => "release_user_funds",
            Self::FailClosed => "fail_closed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiquidityEvidence {
    pub exit_id: String,
    pub reserve_coverage_root: String,
    pub settlement_receipt_root: String,
    pub backstop_pool_root: String,
    pub fee_cap_root: String,
    pub requested_release_piconero: u64,
    pub covered_reserve_piconero: u64,
    pub backstop_available_piconero: u64,
    pub settlement_receipt_piconero: u64,
    pub assessed_fee_bps: u64,
    pub shortfall_piconero: u64,
    pub partial_fill_requested: bool,
    pub partial_fill_allowed: bool,
    pub queue_position: u64,
    pub expected_queue_position: u64,
    pub watcher_attestations: u64,
    pub reserve_proof_height: u64,
    pub l2_tip_height: u64,
}

impl LiquidityEvidence {
    pub fn devnet(exit_id: &str, config: &Config) -> Self {
        let requested_release_piconero = 2_400_000_000_000;
        let covered_reserve_piconero = 2_100_000_000_000;
        let backstop_available_piconero = 300_000_000_000;
        let settlement_receipt_piconero = 2_400_000_000_000;
        let l2_tip_height = 88_320;
        let reserve_proof_height = 88_308;
        let shortfall_piconero =
            requested_release_piconero.saturating_sub(covered_reserve_piconero);

        Self {
            exit_id: exit_id.to_string(),
            reserve_coverage_root: lane_seed_root(
                "reserve-coverage",
                exit_id,
                requested_release_piconero,
                covered_reserve_piconero,
            ),
            settlement_receipt_root: lane_seed_root(
                "settlement-receipt",
                exit_id,
                settlement_receipt_piconero,
                0,
            ),
            backstop_pool_root: lane_seed_root(
                "backstop-pool",
                exit_id,
                backstop_available_piconero,
                shortfall_piconero,
            ),
            fee_cap_root: lane_seed_root("fee-cap", exit_id, config.max_release_fee_bps, 32),
            requested_release_piconero,
            covered_reserve_piconero,
            backstop_available_piconero,
            settlement_receipt_piconero,
            assessed_fee_bps: 32,
            shortfall_piconero,
            partial_fill_requested: false,
            partial_fill_allowed: config.allow_partial_fill,
            queue_position: 7,
            expected_queue_position: 7,
            watcher_attestations: config.watcher_quorum_threshold,
            reserve_proof_height,
            l2_tip_height,
        }
    }

    pub fn evidence_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:liquidity-evidence-root"),
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "exit_id": self.exit_id,
            "reserve_coverage_root": self.reserve_coverage_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "backstop_pool_root": self.backstop_pool_root,
            "fee_cap_root": self.fee_cap_root,
            "requested_release_piconero": self.requested_release_piconero,
            "covered_reserve_piconero": self.covered_reserve_piconero,
            "backstop_available_piconero": self.backstop_available_piconero,
            "settlement_receipt_piconero": self.settlement_receipt_piconero,
            "assessed_fee_bps": self.assessed_fee_bps,
            "shortfall_piconero": self.shortfall_piconero,
            "partial_fill_requested": self.partial_fill_requested,
            "partial_fill_allowed": self.partial_fill_allowed,
            "queue_position": self.queue_position,
            "expected_queue_position": self.expected_queue_position,
            "watcher_attestations": self.watcher_attestations,
            "reserve_proof_height": self.reserve_proof_height,
            "l2_tip_height": self.l2_tip_height,
            "evidence_root": self.evidence_root(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationLane {
    pub lane: LaneKind,
    pub accepted: bool,
    pub fail_closed_reason: String,
    pub evidence_root: String,
    pub lane_root: String,
}

impl VerificationLane {
    pub fn new(
        lane: LaneKind,
        accepted: bool,
        fail_closed_reason: &str,
        evidence_root: &str,
    ) -> Self {
        let lane_record = json!({
            "lane": lane.as_str(),
            "accepted": accepted,
            "fail_closed_reason": fail_closed_reason,
            "evidence_root": evidence_root,
        });

        Self {
            lane,
            accepted,
            fail_closed_reason: fail_closed_reason.to_string(),
            evidence_root: evidence_root.to_string(),
            lane_root: domain_hash(
                &format!("{DOMAIN}:verification-lane-root"),
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Json(&lane_record),
                ],
                32,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "accepted": self.accepted,
            "fail_closed_reason": self.fail_closed_reason,
            "evidence_root": self.evidence_root,
            "lane_root": self.lane_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationReport {
    pub exit_id: String,
    pub verdict: ReleaseVerdict,
    pub lanes: Vec<VerificationLane>,
    pub release_amount_piconero: u64,
    pub lane_root: String,
    pub report_root: String,
}

impl VerificationReport {
    pub fn verify(config: &Config, evidence: &LiquidityEvidence) -> Self {
        let evidence_root = evidence.evidence_root();
        let total_coverage = evidence
            .covered_reserve_piconero
            .saturating_add(evidence.backstop_available_piconero);
        let freshness_lag = evidence
            .l2_tip_height
            .saturating_sub(evidence.reserve_proof_height);
        let shortfall_resolved = evidence.shortfall_piconero == 0
            || (config.require_backstop_for_shortfall
                && evidence.backstop_available_piconero >= evidence.shortfall_piconero);
        let partial_fill_valid = !evidence.partial_fill_requested || evidence.partial_fill_allowed;
        let queue_fair = evidence.queue_position == evidence.expected_queue_position
            && evidence.queue_position <= config.queue_priority_ceiling;
        let reserve_covered = total_coverage >= evidence.requested_release_piconero;
        let receipt_matches =
            evidence.settlement_receipt_piconero == evidence.requested_release_piconero;
        let fee_accepted = evidence.assessed_fee_bps <= config.max_release_fee_bps;
        let quorum_met = evidence.watcher_attestations >= config.watcher_quorum_threshold;
        let reserve_fresh = freshness_lag <= config.reserve_freshness_window_blocks;
        let final_release = reserve_covered
            && receipt_matches
            && shortfall_resolved
            && partial_fill_valid
            && queue_fair
            && fee_accepted
            && quorum_met
            && reserve_fresh;
        let verdict = if final_release {
            ReleaseVerdict::ReleaseUserFunds
        } else {
            ReleaseVerdict::FailClosed
        };

        let mut lanes = vec![
            VerificationLane::new(
                LaneKind::ReserveCoverageRoot,
                reserve_covered,
                reason(reserve_covered, "undercoverage"),
                &evidence_root,
            ),
            VerificationLane::new(
                LaneKind::SettlementReceiptRoot,
                receipt_matches,
                reason(receipt_matches, "settlement_receipt_mismatch"),
                &evidence_root,
            ),
            VerificationLane::new(
                LaneKind::BackstopPoolRoot,
                shortfall_resolved,
                reason(shortfall_resolved, "unresolved_shortfall"),
                &evidence_root,
            ),
            VerificationLane::new(
                LaneKind::FeeCapRoot,
                fee_accepted,
                reason(fee_accepted, "excessive_fee"),
                &evidence_root,
            ),
            VerificationLane::new(
                LaneKind::ShortfallAmount,
                shortfall_resolved,
                reason(shortfall_resolved, "unresolved_shortfall"),
                &evidence_root,
            ),
            VerificationLane::new(
                LaneKind::PartialFillPolicy,
                partial_fill_valid,
                reason(partial_fill_valid, "partial_fill_not_authorized"),
                &evidence_root,
            ),
            VerificationLane::new(
                LaneKind::QueuePriority,
                queue_fair,
                reason(queue_fair, "unfair_queue_order"),
                &evidence_root,
            ),
            VerificationLane::new(
                LaneKind::WatcherQuorum,
                quorum_met,
                reason(quorum_met, "missing_watcher_quorum"),
                &evidence_root,
            ),
            VerificationLane::new(
                LaneKind::ReserveFreshness,
                reserve_fresh,
                reason(reserve_fresh, "stale_reserve_proof"),
                &evidence_root,
            ),
        ];
        lanes.push(VerificationLane::new(
            LaneKind::FinalUserReleaseVerdict,
            final_release,
            reason(final_release, "release_blocked_by_fail_closed_lane"),
            &evidence_root,
        ));

        let release_amount_piconero = if final_release {
            evidence.requested_release_piconero
        } else {
            0
        };
        let lane_records = lanes
            .iter()
            .map(VerificationLane::public_record)
            .collect::<Vec<_>>();
        let lane_root = merkle_root(&format!("{DOMAIN}:verification-lanes"), &lane_records);
        let report_record = json!({
            "exit_id": evidence.exit_id,
            "verdict": verdict.as_str(),
            "release_amount_piconero": release_amount_piconero,
            "lane_root": lane_root,
            "evidence_root": evidence_root,
        });

        Self {
            exit_id: evidence.exit_id.clone(),
            verdict,
            lanes,
            release_amount_piconero,
            lane_root,
            report_root: domain_hash(
                &format!("{DOMAIN}:verification-report-root"),
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Json(&report_record),
                ],
                32,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "exit_id": self.exit_id,
            "verdict": self.verdict.as_str(),
            "release_amount_piconero": self.release_amount_piconero,
            "lanes": self.lanes.iter().map(VerificationLane::public_record).collect::<Vec<_>>(),
            "lane_root": self.lane_root,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub evidence: LiquidityEvidence,
    pub report: VerificationReport,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let evidence =
            LiquidityEvidence::devnet("forced-exit-liquidity-release-devnet-0007", &config);
        let report = VerificationReport::verify(&config, &evidence);

        Self {
            config,
            runtime_id: runtime_id(),
            evidence,
            report,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_liquidity_settlement_release_verification_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "runtime_id": self.runtime_id,
            "config": self.config.public_record(),
            "evidence": self.evidence.public_record(),
            "verification_report": self.report.public_record(),
            "lane_root": self.report.lane_root,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:state-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(SCHEMA_VERSION),
                HashPart::Str(&self.runtime_id),
                HashPart::Json(&self.config.public_record()),
                HashPart::Str(&self.evidence.evidence_root()),
                HashPart::Str(&self.report.lane_root),
                HashPart::Str(&self.report.report_root),
            ],
            32,
        )
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

pub fn verify_liquidity_settlement_release(
    config: &Config,
    evidence: &LiquidityEvidence,
) -> MoneroL2PqBridgeExitCanonicalVerticalSliceLiquiditySettlementReleaseVerificationRuntimeResult<
    VerificationReport,
> {
    let report = VerificationReport::verify(config, evidence);
    if report.verdict == ReleaseVerdict::ReleaseUserFunds {
        Ok(report)
    } else {
        Err(report.report_root)
    }
}

fn runtime_id() -> String {
    domain_hash(
        &format!("{DOMAIN}:runtime-id"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(SCHEMA_VERSION),
        ],
        16,
    )
}

fn lane_seed_root(label: &str, exit_id: &str, left: u64, right: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(exit_id),
            HashPart::U64(left),
            HashPart::U64(right),
        ],
        32,
    )
}

fn reason<'a>(accepted: bool, fail_closed_reason: &'a str) -> &'a str {
    if accepted {
        "none"
    } else {
        fail_closed_reason
    }
}
