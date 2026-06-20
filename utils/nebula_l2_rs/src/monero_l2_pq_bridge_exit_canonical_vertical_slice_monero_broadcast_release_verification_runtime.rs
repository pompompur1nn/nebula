use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceMoneroBroadcastReleaseVerificationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_MONERO_BROADCAST_RELEASE_VERIFICATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-monero-broadcast-release-verification-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_MONERO_BROADCAST_RELEASE_VERIFICATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VERIFICATION_SUITE: &str =
    "monero-l2-pq-bridge-forced-exit-broadcast-release-verification-v1";
pub const DEFAULT_NETWORK: &str = "monero-devnet";
pub const DEFAULT_EXIT_ID: &str =
    "forced-exit-canonical-vertical-slice-monero-broadcast-release-devnet-001";
pub const DEFAULT_WATCHER_SET_ID: &str = "monero-broadcast-release-verification-watchers-devnet-v1";
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 20;
pub const DEFAULT_REORG_WINDOW_BLOCKS: u64 = 16;
pub const DEFAULT_MAX_RECEIPT_AGE_BLOCKS: u64 = 72;
pub const DEFAULT_MAX_FEE_PICONERO: u64 = 18_000_000;
pub const DEFAULT_MIN_RING_MEMBERS: u64 = 16;
pub const DEFAULT_MAX_RING_MEMBERS: u64 = 64;
pub const DEFAULT_MIN_WATCHER_QUORUM_WEIGHT: u64 = 67;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub verification_suite: String,
    pub network: String,
    pub watcher_set_id: String,
    pub min_confirmations: u64,
    pub reorg_window_blocks: u64,
    pub max_receipt_age_blocks: u64,
    pub max_fee_piconero: u64,
    pub min_ring_members: u64,
    pub max_ring_members: u64,
    pub min_watcher_quorum_weight: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            verification_suite: VERIFICATION_SUITE.to_string(),
            network: DEFAULT_NETWORK.to_string(),
            watcher_set_id: DEFAULT_WATCHER_SET_ID.to_string(),
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            reorg_window_blocks: DEFAULT_REORG_WINDOW_BLOCKS,
            max_receipt_age_blocks: DEFAULT_MAX_RECEIPT_AGE_BLOCKS,
            max_fee_piconero: DEFAULT_MAX_FEE_PICONERO,
            min_ring_members: DEFAULT_MIN_RING_MEMBERS,
            max_ring_members: DEFAULT_MAX_RING_MEMBERS,
            min_watcher_quorum_weight: DEFAULT_MIN_WATCHER_QUORUM_WEIGHT,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "verification_suite": self.verification_suite,
            "network": self.network,
            "watcher_set_id": self.watcher_set_id,
            "min_confirmations": self.min_confirmations,
            "reorg_window_blocks": self.reorg_window_blocks,
            "max_receipt_age_blocks": self.max_receipt_age_blocks,
            "max_fee_piconero": self.max_fee_piconero,
            "min_ring_members": self.min_ring_members,
            "max_ring_members": self.max_ring_members,
            "min_watcher_quorum_weight": self.min_watcher_quorum_weight
        })
    }

    pub fn config_root(&self) -> String {
        domain_hash(
            "MONERO-BROADCAST-RELEASE-VERIFICATION-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Release,
    Hold,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Hold => "hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReason {
    PlannedObservedRootMismatch,
    TxidCommitmentMismatch,
    DestinationCommitmentMismatch,
    AmountCommitmentMismatch,
    StaleHeight,
    InsufficientConfirmations,
    FeeCapBreach,
    ReorgRisk,
    RingMemberPrivacyBudgetBreach,
    MissingObserverQuorum,
}

impl HoldReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlannedObservedRootMismatch => "planned_observed_root_mismatch",
            Self::TxidCommitmentMismatch => "txid_commitment_mismatch",
            Self::DestinationCommitmentMismatch => "destination_commitment_mismatch",
            Self::AmountCommitmentMismatch => "amount_commitment_mismatch",
            Self::StaleHeight => "stale_height",
            Self::InsufficientConfirmations => "insufficient_confirmations",
            Self::FeeCapBreach => "fee_cap_breach",
            Self::ReorgRisk => "reorg_risk",
            Self::RingMemberPrivacyBudgetBreach => "ring_member_privacy_budget_breach",
            Self::MissingObserverQuorum => "missing_observer_quorum",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BroadcastEvidence {
    pub exit_id: String,
    pub planned_tx_root: String,
    pub observed_tx_root: String,
    pub expected_txid_commitment: String,
    pub observed_txid_commitment: String,
    pub expected_destination_commitment: String,
    pub observed_destination_commitment: String,
    pub expected_amount_commitment: String,
    pub observed_amount_commitment: String,
    pub broadcast_height: u64,
    pub observed_height: u64,
    pub current_height: u64,
    pub confirmations: u64,
    pub fee_piconero: u64,
    pub ring_members: u64,
    pub watcher_quorum_weight: u64,
    pub competing_reorg_depth: u64,
}

impl BroadcastEvidence {
    pub fn devnet(config: &Config) -> Self {
        let planned_tx_root = lane_commitment("planned_tx_root", DEFAULT_EXIT_ID, "release-plan");
        let txid_commitment = lane_commitment("txid_commitment", DEFAULT_EXIT_ID, "txid");
        let destination_commitment =
            lane_commitment("destination_commitment", DEFAULT_EXIT_ID, "destination");
        let amount_commitment = lane_commitment("amount_commitment", DEFAULT_EXIT_ID, "amount");
        let current_height = 3_514_360;
        let broadcast_height = 3_514_336;

        Self {
            exit_id: DEFAULT_EXIT_ID.to_string(),
            planned_tx_root: planned_tx_root.clone(),
            observed_tx_root: planned_tx_root,
            expected_txid_commitment: txid_commitment.clone(),
            observed_txid_commitment: txid_commitment,
            expected_destination_commitment: destination_commitment.clone(),
            observed_destination_commitment: destination_commitment,
            expected_amount_commitment: amount_commitment.clone(),
            observed_amount_commitment: amount_commitment,
            broadcast_height,
            observed_height: current_height - 1,
            current_height,
            confirmations: current_height - broadcast_height,
            fee_piconero: config.max_fee_piconero - 250_000,
            ring_members: config.min_ring_members,
            watcher_quorum_weight: config.min_watcher_quorum_weight,
            competing_reorg_depth: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "exit_id": self.exit_id,
            "planned_tx_root": self.planned_tx_root,
            "observed_tx_root": self.observed_tx_root,
            "expected_txid_commitment": self.expected_txid_commitment,
            "observed_txid_commitment": self.observed_txid_commitment,
            "expected_destination_commitment": self.expected_destination_commitment,
            "observed_destination_commitment": self.observed_destination_commitment,
            "expected_amount_commitment": self.expected_amount_commitment,
            "observed_amount_commitment": self.observed_amount_commitment,
            "broadcast_height": self.broadcast_height,
            "observed_height": self.observed_height,
            "current_height": self.current_height,
            "confirmations": self.confirmations,
            "fee_piconero": self.fee_piconero,
            "ring_members": self.ring_members,
            "watcher_quorum_weight": self.watcher_quorum_weight,
            "competing_reorg_depth": self.competing_reorg_depth
        })
    }

    pub fn evidence_root(&self) -> String {
        domain_hash(
            "MONERO-BROADCAST-RELEASE-VERIFICATION-EVIDENCE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LaneCheck {
    pub lane: String,
    pub passed: bool,
    pub hold_reason: Option<HoldReason>,
    pub expected_root: String,
    pub observed_root: String,
}

impl LaneCheck {
    pub fn public_record(&self) -> Value {
        let hold_reason = match self.hold_reason {
            Some(reason) => reason.as_str(),
            None => "none",
        };

        json!({
            "lane": self.lane,
            "passed": self.passed,
            "hold_reason": hold_reason,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root
        })
    }

    pub fn lane_root(&self) -> String {
        domain_hash(
            "MONERO-BROADCAST-RELEASE-VERIFICATION-LANE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationSummary {
    pub verdict: Verdict,
    pub release_authorized: bool,
    pub hold_reasons: Vec<String>,
    pub lane_root: String,
}

impl VerificationSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "verdict": self.verdict.as_str(),
            "release_authorized": self.release_authorized,
            "hold_reasons": self.hold_reasons,
            "lane_root": self.lane_root
        })
    }

    pub fn summary_root(&self) -> String {
        domain_hash(
            "MONERO-BROADCAST-RELEASE-VERIFICATION-SUMMARY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub evidence: BroadcastEvidence,
    pub lane_checks: Vec<LaneCheck>,
    pub summary: VerificationSummary,
}

impl State {
    pub fn from_evidence(config: Config, evidence: BroadcastEvidence) -> Self {
        let lane_checks = build_lane_checks(&config, &evidence);
        let hold_reasons = lane_checks
            .iter()
            .filter_map(|lane| lane.hold_reason.map(|reason| reason.as_str().to_string()))
            .collect::<Vec<_>>();
        let release_authorized = hold_reasons.is_empty();
        let verdict = if release_authorized {
            Verdict::Release
        } else {
            Verdict::Hold
        };
        let lane_root = lane_set_root(&lane_checks);
        let summary = VerificationSummary {
            verdict,
            release_authorized,
            hold_reasons,
            lane_root,
        };

        Self {
            config,
            evidence,
            lane_checks,
            summary,
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let evidence = BroadcastEvidence::devnet(&config);
        Self::from_evidence(config, evidence)
    }

    pub fn public_record(&self) -> Value {
        let lanes = self
            .lane_checks
            .iter()
            .map(LaneCheck::public_record)
            .collect::<Vec<_>>();

        json!({
            "config": self.config.public_record(),
            "evidence": self.evidence.public_record(),
            "lane_checks": lanes,
            "summary": self.summary.public_record(),
            "roots": {
                "config_root": self.config.config_root(),
                "evidence_root": self.evidence.evidence_root(),
                "summary_root": self.summary.summary_root()
            }
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-BROADCAST-RELEASE-VERIFICATION-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.config_root()),
                HashPart::Str(&self.evidence.evidence_root()),
                HashPart::Str(&self.summary.summary_root()),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }

    pub fn verify(&self) -> Result<Verdict> {
        if self.summary.release_authorized {
            Ok(Verdict::Release)
        } else {
            Err(self.summary.hold_reasons.join(","))
        }
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

fn build_lane_checks(config: &Config, evidence: &BroadcastEvidence) -> Vec<LaneCheck> {
    vec![
        compare_lane(
            "planned_tx_root",
            &evidence.planned_tx_root,
            &evidence.observed_tx_root,
            HoldReason::PlannedObservedRootMismatch,
        ),
        compare_lane(
            "txid_commitment",
            &evidence.expected_txid_commitment,
            &evidence.observed_txid_commitment,
            HoldReason::TxidCommitmentMismatch,
        ),
        compare_lane(
            "destination_commitment",
            &evidence.expected_destination_commitment,
            &evidence.observed_destination_commitment,
            HoldReason::DestinationCommitmentMismatch,
        ),
        compare_lane(
            "amount_commitment",
            &evidence.expected_amount_commitment,
            &evidence.observed_amount_commitment,
            HoldReason::AmountCommitmentMismatch,
        ),
        threshold_lane(
            "stale_height",
            evidence
                .current_height
                .saturating_sub(evidence.observed_height),
            config.max_receipt_age_blocks,
            true,
            HoldReason::StaleHeight,
        ),
        threshold_lane(
            "confirmation_depth",
            evidence.confirmations,
            config.min_confirmations,
            false,
            HoldReason::InsufficientConfirmations,
        ),
        threshold_lane(
            "fee_cap",
            evidence.fee_piconero,
            config.max_fee_piconero,
            true,
            HoldReason::FeeCapBreach,
        ),
        threshold_lane(
            "finality_reorg_window",
            evidence.competing_reorg_depth,
            config.reorg_window_blocks,
            true,
            HoldReason::ReorgRisk,
        ),
        privacy_budget_lane(config, evidence),
        threshold_lane(
            "watcher_quorum",
            evidence.watcher_quorum_weight,
            config.min_watcher_quorum_weight,
            false,
            HoldReason::MissingObserverQuorum,
        ),
    ]
}

fn compare_lane(
    lane: &str,
    expected_root: &str,
    observed_root: &str,
    hold_reason: HoldReason,
) -> LaneCheck {
    let passed = expected_root == observed_root;

    LaneCheck {
        lane: lane.to_string(),
        passed,
        hold_reason: if passed { None } else { Some(hold_reason) },
        expected_root: expected_root.to_string(),
        observed_root: observed_root.to_string(),
    }
}

fn threshold_lane(
    lane: &str,
    observed: u64,
    threshold: u64,
    maximum: bool,
    hold_reason: HoldReason,
) -> LaneCheck {
    let passed = if maximum {
        observed <= threshold
    } else {
        observed >= threshold
    };
    let expected_root = threshold_root(lane, threshold, maximum);
    let observed_root = observed_root(lane, observed);

    LaneCheck {
        lane: lane.to_string(),
        passed,
        hold_reason: if passed { None } else { Some(hold_reason) },
        expected_root,
        observed_root,
    }
}

fn privacy_budget_lane(config: &Config, evidence: &BroadcastEvidence) -> LaneCheck {
    let passed = evidence.ring_members >= config.min_ring_members
        && evidence.ring_members <= config.max_ring_members;
    let expected_root = domain_hash(
        "MONERO-BROADCAST-RELEASE-VERIFICATION-PRIVACY-BUDGET",
        &[
            HashPart::U64(config.min_ring_members),
            HashPart::U64(config.max_ring_members),
        ],
        32,
    );
    let observed_root = observed_root("ring_member_privacy_budget", evidence.ring_members);

    LaneCheck {
        lane: "ring_member_privacy_budget".to_string(),
        passed,
        hold_reason: if passed {
            None
        } else {
            Some(HoldReason::RingMemberPrivacyBudgetBreach)
        },
        expected_root,
        observed_root,
    }
}

fn lane_set_root(lanes: &[LaneCheck]) -> String {
    let lane_records = lanes
        .iter()
        .map(|lane| json!({ "lane": lane.lane.as_str(), "lane_root": lane.lane_root() }))
        .collect::<Vec<_>>();

    merkle_root(
        "MONERO-BROADCAST-RELEASE-VERIFICATION-LANE-SET",
        &lane_records,
    )
}

fn lane_commitment(lane: &str, exit_id: &str, label: &str) -> String {
    domain_hash(
        "MONERO-BROADCAST-RELEASE-VERIFICATION-COMMITMENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane),
            HashPart::Str(exit_id),
            HashPart::Str(label),
        ],
        32,
    )
}

fn threshold_root(lane: &str, threshold: u64, maximum: bool) -> String {
    let relation = if maximum { "maximum" } else { "minimum" };

    domain_hash(
        "MONERO-BROADCAST-RELEASE-VERIFICATION-THRESHOLD",
        &[
            HashPart::Str(lane),
            HashPart::Str(relation),
            HashPart::U64(threshold),
        ],
        32,
    )
}

fn observed_root(lane: &str, observed: u64) -> String {
    domain_hash(
        "MONERO-BROADCAST-RELEASE-VERIFICATION-OBSERVED",
        &[HashPart::Str(lane), HashPart::U64(observed)],
        32,
    )
}
