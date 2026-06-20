use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalLiveFeedStubSwapPlanRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_LIVE_FEED_STUB_SWAP_PLAN_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-live-feed-stub-swap-plan-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_LIVE_FEED_STUB_SWAP_PLAN_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SWAP_PLAN_SUITE: &str = "monero-l2-pq-bridge-exit-canonical-live-feed-stub-swap-plan-v1";
pub const DEFAULT_MIN_STUB_LANES: u64 = 5;
pub const DEFAULT_MIN_READY_STUB_LANES: u64 = 5;
pub const DEFAULT_MAX_LIVE_FEED_LAG_BLOCKS: u64 = 2;
pub const DEFAULT_REPLAY_COMPATIBILITY_EPOCHS: u64 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedDomain {
    MoneroHeader,
    DepositLock,
    SettlementReceipt,
    ReserveProof,
    ReorgNotice,
}

impl FeedDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroHeader => "monero_header",
            Self::DepositLock => "deposit_lock",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ReserveProof => "reserve_proof",
            Self::ReorgNotice => "reorg_notice",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneReadiness {
    StubMappedReadyForSwap,
    LiveDeferred,
    FailedClosed,
}

impl LaneReadiness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StubMappedReadyForSwap => "stub_mapped_ready_for_swap",
            Self::LiveDeferred => "live_deferred",
            Self::FailedClosed => "failed_closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapReadinessStatus {
    ReadyWithLiveFeedsDeferred,
    Blocked,
}

impl SwapReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyWithLiveFeedsDeferred => "ready_with_live_feeds_deferred",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub swap_plan_suite: String,
    pub min_stub_lanes: u64,
    pub min_ready_stub_lanes: u64,
    pub max_live_feed_lag_blocks: u64,
    pub replay_compatibility_epochs: u64,
    pub fail_closed_required: bool,
    pub privacy_redaction_required: bool,
    pub live_feed_execution_enabled: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            swap_plan_suite: SWAP_PLAN_SUITE.to_string(),
            min_stub_lanes: DEFAULT_MIN_STUB_LANES,
            min_ready_stub_lanes: DEFAULT_MIN_READY_STUB_LANES,
            max_live_feed_lag_blocks: DEFAULT_MAX_LIVE_FEED_LAG_BLOCKS,
            replay_compatibility_epochs: DEFAULT_REPLAY_COMPATIBILITY_EPOCHS,
            fail_closed_required: true,
            privacy_redaction_required: true,
            live_feed_execution_enabled: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "swap_plan_suite": self.swap_plan_suite,
            "min_stub_lanes": self.min_stub_lanes,
            "min_ready_stub_lanes": self.min_ready_stub_lanes,
            "max_live_feed_lag_blocks": self.max_live_feed_lag_blocks,
            "replay_compatibility_epochs": self.replay_compatibility_epochs,
            "fail_closed_required": self.fail_closed_required,
            "privacy_redaction_required": self.privacy_redaction_required,
            "live_feed_execution_enabled": self.live_feed_execution_enabled,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FreshnessSla {
    pub max_lag_blocks: u64,
    pub monotonic_height_required: bool,
    pub finalized_checkpoint_required: bool,
    pub stale_action: String,
}

impl FreshnessSla {
    pub fn public_record(&self) -> Value {
        json!({
            "max_lag_blocks": self.max_lag_blocks,
            "monotonic_height_required": self.monotonic_height_required,
            "finalized_checkpoint_required": self.finalized_checkpoint_required,
            "stale_action": self.stale_action,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeedStubLane {
    pub lane_id: String,
    pub domain: FeedDomain,
    pub fixture_stub_name: String,
    pub fixture_root: String,
    pub mapped_live_feed: String,
    pub status: LaneReadiness,
    pub replay_compatibility_root: String,
    pub privacy_redaction_root: String,
    pub fail_closed_root: String,
    pub lane_root: String,
}

impl FeedStubLane {
    pub fn new(
        domain: FeedDomain,
        fixture_stub_name: &str,
        mapped_live_feed: &str,
        replay_epochs: u64,
    ) -> Self {
        let fixture_root = fixture_root(domain, fixture_stub_name);
        let replay_compatibility_root =
            replay_compatibility_root(domain, &fixture_root, mapped_live_feed, replay_epochs);
        let privacy_redaction_root = privacy_redaction_root(domain, mapped_live_feed);
        let fail_closed_root = fail_closed_root(domain, mapped_live_feed);
        let status = LaneReadiness::StubMappedReadyForSwap;
        let lane_root = feed_stub_lane_root(
            domain,
            fixture_stub_name,
            &fixture_root,
            mapped_live_feed,
            status,
            &replay_compatibility_root,
            &privacy_redaction_root,
            &fail_closed_root,
        );
        let lane_id = lane_id(domain, &lane_root);
        Self {
            lane_id,
            domain,
            fixture_stub_name: fixture_stub_name.to_string(),
            fixture_root,
            mapped_live_feed: mapped_live_feed.to_string(),
            status,
            replay_compatibility_root,
            privacy_redaction_root,
            fail_closed_root,
            lane_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "domain": self.domain.as_str(),
            "fixture_stub_name": self.fixture_stub_name,
            "fixture_root": self.fixture_root,
            "mapped_live_feed": self.mapped_live_feed,
            "status": self.status.as_str(),
            "replay_compatibility_root": self.replay_compatibility_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "fail_closed_root": self.fail_closed_root,
            "lane_root": self.lane_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveFeedLane {
    pub lane_id: String,
    pub domain: FeedDomain,
    pub provider: String,
    pub status: LaneReadiness,
    pub freshness_sla: FreshnessSla,
    pub deferred_reason: String,
    pub required_payload_root: String,
    pub live_feed_root: String,
}

impl LiveFeedLane {
    pub fn new(
        domain: FeedDomain,
        provider: &str,
        required_payloads: &[&str],
        freshness_sla: FreshnessSla,
    ) -> Self {
        let status = LaneReadiness::LiveDeferred;
        let required_payload_root = required_payload_root(domain, required_payloads);
        let deferred_reason =
            "live feed ingestion remains deferred for heavy-gate fixture execution".to_string();
        let live_feed_root = live_feed_lane_root(
            domain,
            provider,
            status,
            &freshness_sla,
            &required_payload_root,
            &deferred_reason,
        );
        let lane_id = lane_id(domain, &live_feed_root);
        Self {
            lane_id,
            domain,
            provider: provider.to_string(),
            status,
            freshness_sla,
            deferred_reason,
            required_payload_root,
            live_feed_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "domain": self.domain.as_str(),
            "provider": self.provider,
            "status": self.status.as_str(),
            "freshness_sla": self.freshness_sla.public_record(),
            "deferred_reason": self.deferred_reason,
            "required_payload_root": self.required_payload_root,
            "live_feed_root": self.live_feed_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandoffPlan {
    pub handoff_root: String,
    pub stub_lane_root: String,
    pub live_lane_root: String,
    pub freshness_sla_root: String,
    pub replay_compatibility_root: String,
    pub privacy_redaction_root: String,
    pub fail_closed_root: String,
    pub readiness_status: SwapReadinessStatus,
    pub operator_action: String,
}

impl HandoffPlan {
    pub fn public_record(&self) -> Value {
        json!({
            "handoff_root": self.handoff_root,
            "stub_lane_root": self.stub_lane_root,
            "live_lane_root": self.live_lane_root,
            "freshness_sla_root": self.freshness_sla_root,
            "replay_compatibility_root": self.replay_compatibility_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "fail_closed_root": self.fail_closed_root,
            "readiness_status": self.readiness_status.as_str(),
            "operator_action": self.operator_action,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub stub_lanes: Vec<FeedStubLane>,
    pub live_lanes: Vec<LiveFeedLane>,
    pub handoff_plan: HandoffPlan,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let stub_lanes = devnet_stub_lanes(&config);
        let live_lanes = devnet_live_lanes(&config);
        let handoff_plan = build_handoff_plan(&config, &stub_lanes, &live_lanes);
        Self {
            config,
            stub_lanes,
            live_lanes,
            handoff_plan,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "hash_suite": self.config.hash_suite,
            "chain_id": self.config.chain_id,
            "state_root": self.state_root(),
            "readiness_status": self.handoff_plan.readiness_status.as_str(),
            "stub_lane_count": self.stub_lanes.len(),
            "live_lane_count": self.live_lanes.len(),
            "live_feeds_deferred": !self.config.live_feed_execution_enabled,
            "stub_lanes": self.stub_lanes.iter().map(FeedStubLane::public_record).collect::<Vec<_>>(),
            "live_lanes": self.live_lanes.iter().map(LiveFeedLane::public_record).collect::<Vec<_>>(),
            "handoff_plan": self.handoff_plan.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-PLAN-STATE",
            &[
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.handoff_plan.handoff_root),
                HashPart::Str(self.handoff_plan.readiness_status.as_str()),
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

pub fn build_handoff_plan(
    config: &Config,
    stub_lanes: &[FeedStubLane],
    live_lanes: &[LiveFeedLane],
) -> HandoffPlan {
    let stub_records = stub_lanes
        .iter()
        .map(FeedStubLane::public_record)
        .collect::<Vec<_>>();
    let live_records = live_lanes
        .iter()
        .map(LiveFeedLane::public_record)
        .collect::<Vec<_>>();
    let freshness_records = live_lanes
        .iter()
        .map(|lane| {
            json!({
                "domain": lane.domain.as_str(),
                "freshness_sla": lane.freshness_sla.public_record(),
            })
        })
        .collect::<Vec<_>>();
    let replay_records = stub_lanes
        .iter()
        .map(|lane| {
            json!({
                "domain": lane.domain.as_str(),
                "fixture_root": lane.fixture_root,
                "mapped_live_feed": lane.mapped_live_feed,
                "replay_compatibility_root": lane.replay_compatibility_root,
            })
        })
        .collect::<Vec<_>>();
    let privacy_records = stub_lanes
        .iter()
        .map(|lane| {
            json!({
                "domain": lane.domain.as_str(),
                "privacy_redaction_root": lane.privacy_redaction_root,
            })
        })
        .collect::<Vec<_>>();
    let fail_closed_records = stub_lanes
        .iter()
        .map(|lane| {
            json!({
                "domain": lane.domain.as_str(),
                "mapped_live_feed": lane.mapped_live_feed,
                "fail_closed_root": lane.fail_closed_root,
            })
        })
        .collect::<Vec<_>>();
    let stub_lane_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-STUB-LANES",
        &stub_records,
    );
    let live_lane_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-LIVE-LANES",
        &live_records,
    );
    let freshness_sla_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-FRESHNESS",
        &freshness_records,
    );
    let replay_compatibility_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-REPLAY",
        &replay_records,
    );
    let privacy_redaction_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-PRIVACY",
        &privacy_records,
    );
    let fail_closed_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-FAIL-CLOSED",
        &fail_closed_records,
    );
    let readiness_status = if stub_lanes.len() as u64 >= config.min_stub_lanes
        && stub_lanes
            .iter()
            .filter(|lane| lane.status == LaneReadiness::StubMappedReadyForSwap)
            .count() as u64
            >= config.min_ready_stub_lanes
        && live_lanes
            .iter()
            .all(|lane| lane.status == LaneReadiness::LiveDeferred)
        && config.fail_closed_required
        && config.privacy_redaction_required
        && !config.live_feed_execution_enabled
    {
        SwapReadinessStatus::ReadyWithLiveFeedsDeferred
    } else {
        SwapReadinessStatus::Blocked
    };
    let handoff_root = handoff_root(
        readiness_status,
        &stub_lane_root,
        &live_lane_root,
        &freshness_sla_root,
        &replay_compatibility_root,
        &privacy_redaction_root,
        &fail_closed_root,
    );
    HandoffPlan {
        handoff_root,
        stub_lane_root,
        live_lane_root,
        freshness_sla_root,
        replay_compatibility_root,
        privacy_redaction_root,
        fail_closed_root,
        readiness_status,
        operator_action:
            "execute heavy gate with mapped static fixture stubs; keep live feeds deferred until provider attestations are connected"
                .to_string(),
    }
}

fn devnet_stub_lanes(config: &Config) -> Vec<FeedStubLane> {
    vec![
        FeedStubLane::new(
            FeedDomain::MoneroHeader,
            "fixture_monero_header_canonical_tip",
            "live_monero_header_reorg_feed",
            config.replay_compatibility_epochs,
        ),
        FeedStubLane::new(
            FeedDomain::DepositLock,
            "fixture_finalized_deposit_lock_batch",
            "live_deposit_lock_watcher_feed",
            config.replay_compatibility_epochs,
        ),
        FeedStubLane::new(
            FeedDomain::SettlementReceipt,
            "fixture_settlement_receipt_batch",
            "live_settlement_execution_feed",
            config.replay_compatibility_epochs,
        ),
        FeedStubLane::new(
            FeedDomain::ReserveProof,
            "fixture_reserve_sufficiency_epoch",
            "live_reserve_release_feed",
            config.replay_compatibility_epochs,
        ),
        FeedStubLane::new(
            FeedDomain::ReorgNotice,
            "fixture_reorg_notice_none",
            "live_reorg_notification_feed",
            config.replay_compatibility_epochs,
        ),
    ]
}

fn devnet_live_lanes(config: &Config) -> Vec<LiveFeedLane> {
    vec![
        LiveFeedLane::new(
            FeedDomain::MoneroHeader,
            "monero_header_reorg_adapter",
            &["height", "header_hash", "previous_hash", "finality_depth"],
            freshness_sla(config, true),
        ),
        LiveFeedLane::new(
            FeedDomain::DepositLock,
            "deposit_lock_watcher_adapter",
            &[
                "deposit_commitment",
                "lock_txid_root",
                "finalized_height",
                "watcher_quorum_root",
            ],
            freshness_sla(config, true),
        ),
        LiveFeedLane::new(
            FeedDomain::SettlementReceipt,
            "live_settlement_execution_contract",
            &[
                "exit_claim_id",
                "settlement_batch_root",
                "nullifier_root",
                "executor_attestation_root",
            ],
            freshness_sla(config, true),
        ),
        LiveFeedLane::new(
            FeedDomain::ReserveProof,
            "reserve_release_adapter",
            &[
                "reserve_epoch",
                "monero_reserve_root",
                "l2_liability_root",
                "operator_attestation_root",
            ],
            freshness_sla(config, true),
        ),
        LiveFeedLane::new(
            FeedDomain::ReorgNotice,
            "monero_header_reorg_adapter",
            &[
                "fork_height",
                "old_tip_hash",
                "new_tip_hash",
                "affected_root",
            ],
            freshness_sla(config, false),
        ),
    ]
}

fn freshness_sla(config: &Config, finalized_checkpoint_required: bool) -> FreshnessSla {
    FreshnessSla {
        max_lag_blocks: config.max_live_feed_lag_blocks,
        monotonic_height_required: finalized_checkpoint_required,
        finalized_checkpoint_required,
        stale_action: "fail closed and continue fixture-only replay for heavy gate".to_string(),
    }
}

pub fn fixture_root(domain: FeedDomain, fixture_stub_name: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain.as_str()),
            HashPart::Str(fixture_stub_name),
        ],
        32,
    )
}

pub fn replay_compatibility_root(
    domain: FeedDomain,
    fixture_root: &str,
    mapped_live_feed: &str,
    replay_epochs: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-REPLAY-COMPATIBILITY",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(fixture_root),
            HashPart::Str(mapped_live_feed),
            HashPart::U64(replay_epochs),
            HashPart::Str("schema_compatible_redacted_roots_only"),
        ],
        32,
    )
}

pub fn privacy_redaction_root(domain: FeedDomain, mapped_live_feed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-PRIVACY-REDACTION",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(mapped_live_feed),
            HashPart::Str("wallet_metadata_redacted"),
            HashPart::Str("amounts_commitment_only"),
            HashPart::Str("addresses_never_public"),
        ],
        32,
    )
}

pub fn fail_closed_root(domain: FeedDomain, mapped_live_feed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-FAIL-CLOSED",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(mapped_live_feed),
            HashPart::Str("missing_or_stale_live_feed_blocks_release"),
            HashPart::Str("fixture_replay_remains_authoritative_for_heavy_gate"),
        ],
        32,
    )
}

pub fn required_payload_root(domain: FeedDomain, required_payloads: &[&str]) -> String {
    let records = required_payloads
        .iter()
        .map(|payload| json!({ "domain": domain.as_str(), "payload": payload }))
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-REQUIRED-PAYLOADS",
        &records,
    )
}

pub fn lane_id(domain: FeedDomain, lane_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-LANE-ID",
        &[HashPart::Str(domain.as_str()), HashPart::Str(lane_root)],
        16,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn feed_stub_lane_root(
    domain: FeedDomain,
    fixture_stub_name: &str,
    fixture_root: &str,
    mapped_live_feed: &str,
    status: LaneReadiness,
    replay_compatibility_root: &str,
    privacy_redaction_root: &str,
    fail_closed_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-STUB-LANE",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(fixture_stub_name),
            HashPart::Str(fixture_root),
            HashPart::Str(mapped_live_feed),
            HashPart::Str(status.as_str()),
            HashPart::Str(replay_compatibility_root),
            HashPart::Str(privacy_redaction_root),
            HashPart::Str(fail_closed_root),
        ],
        32,
    )
}

pub fn live_feed_lane_root(
    domain: FeedDomain,
    provider: &str,
    status: LaneReadiness,
    freshness_sla: &FreshnessSla,
    required_payload_root: &str,
    deferred_reason: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-LIVE-LANE",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(provider),
            HashPart::Str(status.as_str()),
            HashPart::Json(&freshness_sla.public_record()),
            HashPart::Str(required_payload_root),
            HashPart::Str(deferred_reason),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn handoff_root(
    readiness_status: SwapReadinessStatus,
    stub_lane_root: &str,
    live_lane_root: &str,
    freshness_sla_root: &str,
    replay_compatibility_root: &str,
    privacy_redaction_root: &str,
    fail_closed_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-HANDOFF",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(readiness_status.as_str()),
            HashPart::Str(stub_lane_root),
            HashPart::Str(live_lane_root),
            HashPart::Str(freshness_sla_root),
            HashPart::Str(replay_compatibility_root),
            HashPart::Str(privacy_redaction_root),
            HashPart::Str(fail_closed_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIVE-FEED-STUB-SWAP-PLAN-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}
