use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalLiveFeedBoundaryContractRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_LIVE_FEED_BOUNDARY_CONTRACT_RUNTIME_PROTOCOL_VERSION:
    &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-live-feed-boundary-contract-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_LIVE_FEED_BOUNDARY_CONTRACT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BOUNDARY_CONTRACT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-live-feed-boundary-contract-v1";
pub const DEFAULT_MIN_FEED_LANES: u64 = 8;
pub const DEFAULT_MONERO_HEADER_FRESHNESS_BLOCKS: u64 = 2;
pub const DEFAULT_DEPOSIT_LOCK_FRESHNESS_BLOCKS: u64 = 4;
pub const DEFAULT_REORG_NOTIFICATION_FRESHNESS_BLOCKS: u64 = 1;
pub const DEFAULT_SETTLEMENT_RECEIPT_FRESHNESS_L2_BLOCKS: u64 = 2;
pub const DEFAULT_RESERVE_PROOF_FRESHNESS_L2_BLOCKS: u64 = 5;
pub const DEFAULT_PQ_AUTHORITY_EPOCH_FRESHNESS_L2_BLOCKS: u64 = 12;
pub const DEFAULT_PRIVACY_BUDGET_FRESHNESS_L2_BLOCKS: u64 = 8;
pub const DEFAULT_CHALLENGE_WINDOW_FRESHNESS_L2_BLOCKS: u64 = 1;
pub const DEFAULT_MIN_FINALITY_CONFIRMATIONS: u64 = 20;
pub const DEFAULT_MAX_REORG_DEPTH_BLOCKS: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryStatus {
    SpecifiedNotConnected,
    Connected,
    FailedClosed,
}

impl BoundaryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpecifiedNotConnected => "specified_not_connected",
            Self::Connected => "connected",
            Self::FailedClosed => "failed_closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedLaneKind {
    MoneroHeaders,
    FinalizedDepositLocks,
    ReorgNotifications,
    SettlementReceipts,
    ReserveProofs,
    PqAuthorityEpochs,
    PrivacyBudgetSummaries,
    ForcedExitChallengeWindows,
}

impl FeedLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroHeaders => "monero_headers",
            Self::FinalizedDepositLocks => "finalized_deposit_locks",
            Self::ReorgNotifications => "reorg_notifications",
            Self::SettlementReceipts => "settlement_receipts",
            Self::ReserveProofs => "reserve_proofs",
            Self::PqAuthorityEpochs => "pq_authority_epochs",
            Self::PrivacyBudgetSummaries => "privacy_budget_summaries",
            Self::ForcedExitChallengeWindows => "forced_exit_challenge_windows",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub boundary_contract_suite: String,
    pub min_feed_lanes: u64,
    pub live_feeds_connected: bool,
    pub fail_closed_required: bool,
    pub replay_graduation_allowed: bool,
    pub min_finality_confirmations: u64,
    pub max_reorg_depth_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            boundary_contract_suite: BOUNDARY_CONTRACT_SUITE.to_string(),
            min_feed_lanes: DEFAULT_MIN_FEED_LANES,
            live_feeds_connected: false,
            fail_closed_required: true,
            replay_graduation_allowed: false,
            min_finality_confirmations: DEFAULT_MIN_FINALITY_CONFIRMATIONS,
            max_reorg_depth_blocks: DEFAULT_MAX_REORG_DEPTH_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "boundary_contract_suite": self.boundary_contract_suite,
            "min_feed_lanes": self.min_feed_lanes,
            "live_feeds_connected": self.live_feeds_connected,
            "fail_closed_required": self.fail_closed_required,
            "replay_graduation_allowed": self.replay_graduation_allowed,
            "min_finality_confirmations": self.min_finality_confirmations,
            "max_reorg_depth_blocks": self.max_reorg_depth_blocks,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FreshnessWindow {
    pub max_source_lag_blocks: u64,
    pub max_observer_lag_blocks: u64,
    pub requires_monotonic_height: bool,
    pub requires_finalized_checkpoint: bool,
}

impl FreshnessWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "max_source_lag_blocks": self.max_source_lag_blocks,
            "max_observer_lag_blocks": self.max_observer_lag_blocks,
            "requires_monotonic_height": self.requires_monotonic_height,
            "requires_finalized_checkpoint": self.requires_finalized_checkpoint,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeedLaneContract {
    pub lane_id: String,
    pub kind: FeedLaneKind,
    pub status: BoundaryStatus,
    pub provider_surface: String,
    pub required_payloads: Vec<String>,
    pub freshness: FreshnessWindow,
    pub root_commitment: String,
    pub fail_closed_requirement: String,
    pub replay_graduation_requirement: String,
}

impl FeedLaneContract {
    pub fn new(
        kind: FeedLaneKind,
        provider_surface: impl Into<String>,
        required_payloads: Vec<&'static str>,
        freshness: FreshnessWindow,
        fail_closed_requirement: impl Into<String>,
        replay_graduation_requirement: impl Into<String>,
    ) -> Self {
        let provider_surface = provider_surface.into();
        let required_payloads = required_payloads
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let fail_closed_requirement = fail_closed_requirement.into();
        let replay_graduation_requirement = replay_graduation_requirement.into();
        let status = BoundaryStatus::SpecifiedNotConnected;
        let root_commitment = feed_lane_root(
            kind,
            status,
            &provider_surface,
            &required_payloads,
            &freshness,
            &fail_closed_requirement,
            &replay_graduation_requirement,
        );
        let lane_id = feed_lane_id(kind, &root_commitment);
        Self {
            lane_id,
            kind,
            status,
            provider_surface,
            required_payloads,
            freshness,
            root_commitment,
            fail_closed_requirement,
            replay_graduation_requirement,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "provider_surface": self.provider_surface,
            "required_payloads": self.required_payloads,
            "freshness": self.freshness.public_record(),
            "root_commitment": self.root_commitment,
            "fail_closed_requirement": self.fail_closed_requirement,
            "replay_graduation_requirement": self.replay_graduation_requirement,
        })
    }

    pub fn state_root(&self) -> String {
        self.root_commitment.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BoundaryPolicy {
    pub status: BoundaryStatus,
    pub live_feeds_specified: bool,
    pub live_feeds_connected: bool,
    pub static_fixture_replay_only: bool,
    pub fail_closed_on_missing_header: bool,
    pub fail_closed_on_reorg_gap: bool,
    pub fail_closed_on_deposit_gap: bool,
    pub fail_closed_on_settlement_gap: bool,
    pub fail_closed_on_reserve_gap: bool,
    pub fail_closed_on_pq_epoch_gap: bool,
    pub fail_closed_on_privacy_budget_gap: bool,
    pub fail_closed_on_challenge_window_gap: bool,
    pub release_candidate_answer: String,
}

impl BoundaryPolicy {
    pub fn devnet() -> Self {
        Self {
            status: BoundaryStatus::SpecifiedNotConnected,
            live_feeds_specified: true,
            live_feeds_connected: false,
            static_fixture_replay_only: true,
            fail_closed_on_missing_header: true,
            fail_closed_on_reorg_gap: true,
            fail_closed_on_deposit_gap: true,
            fail_closed_on_settlement_gap: true,
            fail_closed_on_reserve_gap: true,
            fail_closed_on_pq_epoch_gap: true,
            fail_closed_on_privacy_budget_gap: true,
            fail_closed_on_challenge_window_gap: true,
            release_candidate_answer:
                "live_feed_boundary_specified_but_not_connected_static_fixtures_remain_the_limit"
                    .to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "live_feeds_specified": self.live_feeds_specified,
            "live_feeds_connected": self.live_feeds_connected,
            "static_fixture_replay_only": self.static_fixture_replay_only,
            "fail_closed_on_missing_header": self.fail_closed_on_missing_header,
            "fail_closed_on_reorg_gap": self.fail_closed_on_reorg_gap,
            "fail_closed_on_deposit_gap": self.fail_closed_on_deposit_gap,
            "fail_closed_on_settlement_gap": self.fail_closed_on_settlement_gap,
            "fail_closed_on_reserve_gap": self.fail_closed_on_reserve_gap,
            "fail_closed_on_pq_epoch_gap": self.fail_closed_on_pq_epoch_gap,
            "fail_closed_on_privacy_budget_gap": self.fail_closed_on_privacy_budget_gap,
            "fail_closed_on_challenge_window_gap": self.fail_closed_on_challenge_window_gap,
            "release_candidate_answer": self.release_candidate_answer,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("boundary_policy", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RootCommitments {
    pub config_root: String,
    pub feed_lane_root: String,
    pub freshness_root: String,
    pub fail_closed_root: String,
    pub policy_root: String,
    pub state_root: String,
}

impl RootCommitments {
    pub fn new(config: &Config, feed_lanes: &[FeedLaneContract], policy: &BoundaryPolicy) -> Self {
        let feed_records = feed_lanes
            .iter()
            .map(FeedLaneContract::public_record)
            .collect::<Vec<_>>();
        let freshness_records = feed_lanes
            .iter()
            .map(|lane| {
                json!({
                    "kind": lane.kind.as_str(),
                    "lane_id": lane.lane_id,
                    "freshness": lane.freshness.public_record(),
                })
            })
            .collect::<Vec<_>>();
        let fail_closed_records = feed_lanes
            .iter()
            .map(|lane| {
                json!({
                    "kind": lane.kind.as_str(),
                    "lane_id": lane.lane_id,
                    "status": lane.status.as_str(),
                    "fail_closed_requirement": lane.fail_closed_requirement,
                })
            })
            .collect::<Vec<_>>();
        let mut commitments = Self {
            config_root: config.state_root(),
            feed_lane_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-LANES",
                &feed_records,
            ),
            freshness_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-FRESHNESS",
                &freshness_records,
            ),
            fail_closed_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-FAIL-CLOSED",
                &fail_closed_records,
            ),
            policy_root: policy.state_root(),
            state_root: String::new(),
        };
        commitments.state_root = commitments.compute_state_root();
        commitments
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "feed_lane_root": self.feed_lane_root,
            "freshness_root": self.freshness_root,
            "fail_closed_root": self.fail_closed_root,
            "policy_root": self.policy_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-BOUNDARY-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.feed_lane_root),
                HashPart::Str(&self.freshness_root),
                HashPart::Str(&self.fail_closed_root),
                HashPart::Str(&self.policy_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub status: BoundaryStatus,
    pub feed_lanes: Vec<FeedLaneContract>,
    pub policy: BoundaryPolicy,
    pub root_commitments: RootCommitments,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let feed_lanes = devnet_feed_lanes();
        let policy = BoundaryPolicy::devnet();
        let root_commitments = RootCommitments::new(&config, &feed_lanes, &policy);
        Self {
            config,
            status: BoundaryStatus::SpecifiedNotConnected,
            feed_lanes,
            policy,
            root_commitments,
        }
    }

    pub fn public_record(&self) -> Value {
        let feed_lanes = self
            .feed_lanes
            .iter()
            .map(FeedLaneContract::public_record)
            .collect::<Vec<_>>();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "boundary_contract_suite": self.config.boundary_contract_suite,
            "status": self.status.as_str(),
            "feed_lane_count": self.feed_lanes.len(),
            "feed_lanes": feed_lanes,
            "policy": self.policy.public_record(),
            "root_commitments": self.root_commitments.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.root_commitments.state_root.clone()
    }
}

fn devnet_feed_lanes() -> Vec<FeedLaneContract> {
    vec![
        FeedLaneContract::new(
            FeedLaneKind::MoneroHeaders,
            "monero_header_reorg_adapter",
            vec![
                "height",
                "block_hash",
                "previous_block_hash",
                "pow_difficulty",
                "timestamp",
                "finality_depth",
                "observer_quorum_root",
            ],
            FreshnessWindow {
                max_source_lag_blocks: DEFAULT_MONERO_HEADER_FRESHNESS_BLOCKS,
                max_observer_lag_blocks: DEFAULT_MONERO_HEADER_FRESHNESS_BLOCKS,
                requires_monotonic_height: true,
                requires_finalized_checkpoint: true,
            },
            "pause deposit admission, settlement release, and replay graduation when header continuity or finality depth is absent",
            "static header fixtures must be replaced by signed live header checkpoints with reorg-aware finality depth",
        ),
        FeedLaneContract::new(
            FeedLaneKind::FinalizedDepositLocks,
            "deposit_lock_watcher_adapter",
            vec![
                "deposit_commitment",
                "monero_txid_root",
                "output_commitment_root",
                "lock_height",
                "finalized_height",
                "watcher_quorum_root",
            ],
            FreshnessWindow {
                max_source_lag_blocks: DEFAULT_DEPOSIT_LOCK_FRESHNESS_BLOCKS,
                max_observer_lag_blocks: DEFAULT_DEPOSIT_LOCK_FRESHNESS_BLOCKS,
                requires_monotonic_height: true,
                requires_finalized_checkpoint: true,
            },
            "reject note minting and forced-exit credit when finalized lock evidence is stale, partial, or below quorum",
            "fixture deposit locks must be backed by live finalized lock certificates and watcher quorum commitments",
        ),
        FeedLaneContract::new(
            FeedLaneKind::ReorgNotifications,
            "monero_header_reorg_adapter",
            vec![
                "fork_height",
                "old_tip_hash",
                "new_tip_hash",
                "affected_deposit_root",
                "affected_settlement_root",
                "watcher_attestation_root",
            ],
            FreshnessWindow {
                max_source_lag_blocks: DEFAULT_REORG_NOTIFICATION_FRESHNESS_BLOCKS,
                max_observer_lag_blocks: DEFAULT_REORG_NOTIFICATION_FRESHNESS_BLOCKS,
                requires_monotonic_height: false,
                requires_finalized_checkpoint: false,
            },
            "quarantine affected deposits, exits, and settlement receipts until the new canonical header path is reconciled",
            "reorg fixtures must be replaced by live fork notifications with affected-root enumeration",
        ),
        FeedLaneContract::new(
            FeedLaneKind::SettlementReceipts,
            "live_settlement_execution_contract",
            vec![
                "exit_claim_id",
                "settlement_batch_root",
                "payout_commitment_root",
                "nullifier_root",
                "settled_at_l2_height",
                "executor_attestation_root",
            ],
            FreshnessWindow {
                max_source_lag_blocks: DEFAULT_SETTLEMENT_RECEIPT_FRESHNESS_L2_BLOCKS,
                max_observer_lag_blocks: DEFAULT_SETTLEMENT_RECEIPT_FRESHNESS_L2_BLOCKS,
                requires_monotonic_height: true,
                requires_finalized_checkpoint: true,
            },
            "block reserve release and claim closure when settlement receipts are absent, duplicated, or unfinalized",
            "static settlement receipts must be replaced by live execution receipts keyed by exit claim and nullifier roots",
        ),
        FeedLaneContract::new(
            FeedLaneKind::ReserveProofs,
            "reserve_release_adapter",
            vec![
                "reserve_epoch",
                "monero_reserve_root",
                "l2_liability_root",
                "available_liquidity_units",
                "reserved_exit_liquidity_units",
                "operator_attestation_root",
            ],
            FreshnessWindow {
                max_source_lag_blocks: DEFAULT_RESERVE_PROOF_FRESHNESS_L2_BLOCKS,
                max_observer_lag_blocks: DEFAULT_RESERVE_PROOF_FRESHNESS_L2_BLOCKS,
                requires_monotonic_height: true,
                requires_finalized_checkpoint: true,
            },
            "halt fast release, forced-exit acceleration, and reserve unlocks when reserve proofs are stale or insufficient",
            "liquidity fixtures must be replaced by live reserve proofs tied to liabilities and active exit demand",
        ),
        FeedLaneContract::new(
            FeedLaneKind::PqAuthorityEpochs,
            "pq_authority_key_manager_adapter",
            vec![
                "epoch",
                "authority_set_root",
                "threshold_policy_root",
                "key_rotation_root",
                "revocation_root",
                "signature_scheme_root",
            ],
            FreshnessWindow {
                max_source_lag_blocks: DEFAULT_PQ_AUTHORITY_EPOCH_FRESHNESS_L2_BLOCKS,
                max_observer_lag_blocks: DEFAULT_PQ_AUTHORITY_EPOCH_FRESHNESS_L2_BLOCKS,
                requires_monotonic_height: true,
                requires_finalized_checkpoint: true,
            },
            "reject release authority, upgrades, and watcher quorum attestations when PQ epoch data is stale or revoked",
            "PQ authority fixtures must be replaced by live epoch roots with rotation and revocation commitments",
        ),
        FeedLaneContract::new(
            FeedLaneKind::PrivacyBudgetSummaries,
            "private_receipt_scanner_adapter",
            vec![
                "budget_epoch",
                "receipt_linkage_risk_root",
                "view_tag_exposure_root",
                "decoy_entropy_root",
                "scan_disclosure_root",
                "leakage_budget_remaining_bps",
            ],
            FreshnessWindow {
                max_source_lag_blocks: DEFAULT_PRIVACY_BUDGET_FRESHNESS_L2_BLOCKS,
                max_observer_lag_blocks: DEFAULT_PRIVACY_BUDGET_FRESHNESS_L2_BLOCKS,
                requires_monotonic_height: true,
                requires_finalized_checkpoint: true,
            },
            "fail closed on private transfer replay, receipt publication, and forced-exit disclosure when privacy budget summaries are missing",
            "privacy regression fixtures must be replaced by live summarized leakage budgets without revealing wallet metadata",
        ),
        FeedLaneContract::new(
            FeedLaneKind::ForcedExitChallengeWindows,
            "exit_claim_queue_adapter",
            vec![
                "exit_claim_id",
                "opened_at_l2_height",
                "challenge_deadline_l2_height",
                "open_challenge_root",
                "resolution_root",
                "timeout_policy_root",
            ],
            FreshnessWindow {
                max_source_lag_blocks: DEFAULT_CHALLENGE_WINDOW_FRESHNESS_L2_BLOCKS,
                max_observer_lag_blocks: DEFAULT_CHALLENGE_WINDOW_FRESHNESS_L2_BLOCKS,
                requires_monotonic_height: true,
                requires_finalized_checkpoint: true,
            },
            "prevent claim finalization when challenge windows are stale, skipped, or missing open dispute roots",
            "forced-exit fixtures must be replaced by live challenge-window roots and timeout policy commitments",
        ),
    ]
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

pub fn feed_lane_id(kind: FeedLaneKind, root_commitment: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-LANE-ID",
        &[HashPart::Str(kind.as_str()), HashPart::Str(root_commitment)],
        32,
    )
}

pub fn feed_lane_root(
    kind: FeedLaneKind,
    status: BoundaryStatus,
    provider_surface: &str,
    required_payloads: &[String],
    freshness: &FreshnessWindow,
    fail_closed_requirement: &str,
    replay_graduation_requirement: &str,
) -> String {
    let payload_records = required_payloads
        .iter()
        .map(|payload| json!({ "payload": payload }))
        .collect::<Vec<_>>();
    let payload_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-PAYLOADS",
        &payload_records,
    );
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-LANE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(provider_surface),
            HashPart::Str(&payload_root),
            HashPart::Json(&freshness.public_record()),
            HashPart::Str(fail_closed_requirement),
            HashPart::Str(replay_graduation_requirement),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-BOUNDARY-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}
