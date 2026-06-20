use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeReserveProcessFeedRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RESERVE_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-reserve-process-feed-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RESERVE_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PROCESS_FEED_SUITE: &str =
    "canonical-user-escape-reserve-liquidity-process-feed-devnet-v1";
pub const XMR_ATOMIC_UNITS_PER_XMR: u64 = 1_000_000_000_000;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_WARN_RESERVE_COVERAGE_BPS: u64 = 11_000;
pub const DEFAULT_MIN_WITHDRAWAL_HOLD_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_EXHAUSTION_BLOCKER_BPS: u64 = 9_250;
pub const DEFAULT_MIN_REFRESH_INTERVAL_BLOCKS: u64 = 6;
pub const DEFAULT_MAX_REFRESH_STALENESS_BLOCKS: u64 = 18;
pub const DEFAULT_MIN_RESERVE_PROOF_CONFIRMATIONS: u64 = 10;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofStatus {
    Accepted,
    RefreshRequired,
    Rejected,
}

impl ReserveProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::RefreshRequired => "refresh_required",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockedXmrBucketKind {
    HotRelease,
    WarmReserve,
    ColdReserve,
    ChallengeHoldback,
    EmergencyBackstop,
}

impl LockedXmrBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotRelease => "hot_release",
            Self::WarmReserve => "warm_reserve",
            Self::ColdReserve => "cold_reserve",
            Self::ChallengeHoldback => "challenge_holdback",
            Self::EmergencyBackstop => "emergency_backstop",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessFeedKind {
    ReserveProof,
    LockedBucket,
    WithdrawalHold,
    LiquidityBlocker,
    ReserveRefresh,
}

impl ProcessFeedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveProof => "reserve_proof",
            Self::LockedBucket => "locked_bucket",
            Self::WithdrawalHold => "withdrawal_hold",
            Self::LiquidityBlocker => "liquidity_blocker",
            Self::ReserveRefresh => "reserve_refresh",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerStatus {
    Clear,
    Watch,
    Blocking,
}

impl BlockerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Watch => "watch",
            Self::Blocking => "blocking",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshRequirement {
    Current,
    DueSoon,
    Required,
}

impl RefreshRequirement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::DueSoon => "due_soon",
            Self::Required => "required",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub process_feed_suite: String,
    pub reserve_asset_id: String,
    pub liability_asset_id: String,
    pub min_reserve_coverage_bps: u64,
    pub warn_reserve_coverage_bps: u64,
    pub min_withdrawal_hold_coverage_bps: u64,
    pub exhaustion_blocker_bps: u64,
    pub min_refresh_interval_blocks: u64,
    pub max_refresh_staleness_blocks: u64,
    pub min_reserve_proof_confirmations: u64,
    pub fail_closed_on_blocker: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            process_feed_suite: PROCESS_FEED_SUITE.to_string(),
            reserve_asset_id: "xmr-reserve-devnet".to_string(),
            liability_asset_id: "wxmr-user-escape-devnet".to_string(),
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            warn_reserve_coverage_bps: DEFAULT_WARN_RESERVE_COVERAGE_BPS,
            min_withdrawal_hold_coverage_bps: DEFAULT_MIN_WITHDRAWAL_HOLD_COVERAGE_BPS,
            exhaustion_blocker_bps: DEFAULT_EXHAUSTION_BLOCKER_BPS,
            min_refresh_interval_blocks: DEFAULT_MIN_REFRESH_INTERVAL_BLOCKS,
            max_refresh_staleness_blocks: DEFAULT_MAX_REFRESH_STALENESS_BLOCKS,
            min_reserve_proof_confirmations: DEFAULT_MIN_RESERVE_PROOF_CONFIRMATIONS,
            fail_closed_on_blocker: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "process_feed_suite": self.process_feed_suite,
            "reserve_asset_id": self.reserve_asset_id,
            "liability_asset_id": self.liability_asset_id,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "warn_reserve_coverage_bps": self.warn_reserve_coverage_bps,
            "min_withdrawal_hold_coverage_bps": self.min_withdrawal_hold_coverage_bps,
            "exhaustion_blocker_bps": self.exhaustion_blocker_bps,
            "min_refresh_interval_blocks": self.min_refresh_interval_blocks,
            "max_refresh_staleness_blocks": self.max_refresh_staleness_blocks,
            "min_reserve_proof_confirmations": self.min_reserve_proof_confirmations,
            "fail_closed_on_blocker": self.fail_closed_on_blocker,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveProofObservation {
    pub observation_id: String,
    pub process_feed_id: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub observed_height: u64,
    pub proof_confirmations: u64,
    pub locked_atomic_units: u64,
    pub pending_withdrawal_atomic_units: u64,
    pub coverage_bps: u64,
    pub status: ReserveProofStatus,
}

impl ReserveProofObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "process_feed_id": self.process_feed_id,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "observed_height": self.observed_height,
            "proof_confirmations": self.proof_confirmations,
            "locked_atomic_units": self.locked_atomic_units,
            "pending_withdrawal_atomic_units": self.pending_withdrawal_atomic_units,
            "coverage_bps": self.coverage_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reserve-proof-observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LockedXmrBucket {
    pub bucket_id: String,
    pub kind: LockedXmrBucketKind,
    pub custody_root: String,
    pub locked_atomic_units: u64,
    pub release_eligible_atomic_units: u64,
    pub holdback_atomic_units: u64,
    pub last_refresh_height: u64,
}

impl LockedXmrBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "kind": self.kind.as_str(),
            "custody_root": self.custody_root,
            "locked_atomic_units": self.locked_atomic_units,
            "release_eligible_atomic_units": self.release_eligible_atomic_units,
            "holdback_atomic_units": self.holdback_atomic_units,
            "last_refresh_height": self.last_refresh_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("locked-xmr-bucket", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalHoldCoverage {
    pub hold_id: String,
    pub withdrawal_batch_id: String,
    pub pending_atomic_units: u64,
    pub reserved_atomic_units: u64,
    pub coverage_bps: u64,
    pub covered: bool,
    pub release_after_height: u64,
}

impl WithdrawalHoldCoverage {
    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "withdrawal_batch_id": self.withdrawal_batch_id,
            "pending_atomic_units": self.pending_atomic_units,
            "reserved_atomic_units": self.reserved_atomic_units,
            "coverage_bps": self.coverage_bps,
            "covered": self.covered,
            "release_after_height": self.release_after_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("withdrawal-hold-coverage", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityExhaustionBlocker {
    pub blocker_id: String,
    pub queue_id: String,
    pub requested_atomic_units: u64,
    pub available_atomic_units: u64,
    pub utilization_bps: u64,
    pub status: BlockerStatus,
    pub reason: String,
}

impl LiquidityExhaustionBlocker {
    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "queue_id": self.queue_id,
            "requested_atomic_units": self.requested_atomic_units,
            "available_atomic_units": self.available_atomic_units,
            "utilization_bps": self.utilization_bps,
            "status": self.status.as_str(),
            "reason": self.reason,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("liquidity-exhaustion-blocker", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveRefreshRequirement {
    pub requirement_id: String,
    pub process_feed_id: String,
    pub last_refresh_height: u64,
    pub current_height: u64,
    pub next_required_height: u64,
    pub staleness_blocks: u64,
    pub requirement: RefreshRequirement,
}

impl ReserveRefreshRequirement {
    pub fn public_record(&self) -> Value {
        json!({
            "requirement_id": self.requirement_id,
            "process_feed_id": self.process_feed_id,
            "last_refresh_height": self.last_refresh_height,
            "current_height": self.current_height,
            "next_required_height": self.next_required_height,
            "staleness_blocks": self.staleness_blocks,
            "requirement": self.requirement.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reserve-refresh-requirement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessFeedObservation {
    pub feed_item_id: String,
    pub kind: ProcessFeedKind,
    pub subject_id: String,
    pub payload_root: String,
    pub observed_height: u64,
    pub sequence: u64,
}

impl ProcessFeedObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "feed_item_id": self.feed_item_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "observed_height": self.observed_height,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("process-feed-observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub reserve_proofs: Vec<ReserveProofObservation>,
    pub locked_xmr_buckets: Vec<LockedXmrBucket>,
    pub withdrawal_hold_coverages: Vec<WithdrawalHoldCoverage>,
    pub liquidity_exhaustion_blockers: Vec<LiquidityExhaustionBlocker>,
    pub reserve_refresh_requirements: Vec<ReserveRefreshRequirement>,
    pub process_feed_observations: Vec<ProcessFeedObservation>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let reserve_proofs = vec![
            reserve_proof_observation(
                "reserve-proof-primary-0001",
                "reserve-process-feed-devnet-a",
                1_260_000_000_000_000,
                1_100_000_000_000_000,
                1_145_454_545_454_545,
                1_024,
                14,
                ReserveProofStatus::Accepted,
            ),
            reserve_proof_observation(
                "reserve-proof-refresh-0002",
                "reserve-process-feed-devnet-b",
                790_000_000_000_000,
                760_000_000_000_000,
                1_039_473_684_210_526,
                1_018,
                11,
                ReserveProofStatus::RefreshRequired,
            ),
        ];
        let locked_xmr_buckets = vec![
            locked_xmr_bucket(
                "locked-xmr-hot-release",
                LockedXmrBucketKind::HotRelease,
                360_000_000_000_000,
                295_000_000_000_000,
                65_000_000_000_000,
                1_024,
            ),
            locked_xmr_bucket(
                "locked-xmr-warm-reserve",
                LockedXmrBucketKind::WarmReserve,
                520_000_000_000_000,
                420_000_000_000_000,
                100_000_000_000_000,
                1_020,
            ),
            locked_xmr_bucket(
                "locked-xmr-challenge-holdback",
                LockedXmrBucketKind::ChallengeHoldback,
                140_000_000_000_000,
                40_000_000_000_000,
                100_000_000_000_000,
                1_018,
            ),
        ];
        let withdrawal_hold_coverages = vec![
            withdrawal_hold_coverage(
                "withdrawal-hold-coverage-0001",
                "escape-withdrawal-batch-42",
                240_000_000_000_000,
                260_000_000_000_000,
                1_030,
                config.min_withdrawal_hold_coverage_bps,
            ),
            withdrawal_hold_coverage(
                "withdrawal-hold-coverage-0002",
                "escape-withdrawal-batch-43",
                300_000_000_000_000,
                276_000_000_000_000,
                1_033,
                config.min_withdrawal_hold_coverage_bps,
            ),
        ];
        let liquidity_exhaustion_blockers = vec![
            liquidity_exhaustion_blocker(
                "liquidity-blocker-watch-0001",
                "escape-release-queue-hot",
                290_000_000_000_000,
                310_000_000_000_000,
                config.exhaustion_blocker_bps,
            ),
            liquidity_exhaustion_blocker(
                "liquidity-blocker-active-0002",
                "escape-release-queue-forced",
                430_000_000_000_000,
                320_000_000_000_000,
                config.exhaustion_blocker_bps,
            ),
        ];
        let reserve_refresh_requirements = vec![
            reserve_refresh_requirement(
                "reserve-refresh-current-0001",
                "reserve-process-feed-devnet-a",
                1_024,
                1_030,
                &config,
            ),
            reserve_refresh_requirement(
                "reserve-refresh-required-0002",
                "reserve-process-feed-devnet-b",
                1_010,
                1_033,
                &config,
            ),
        ];
        let process_feed_observations = process_feed_observations(
            &reserve_proofs,
            &locked_xmr_buckets,
            &withdrawal_hold_coverages,
            &liquidity_exhaustion_blockers,
            &reserve_refresh_requirements,
        );
        Self {
            config,
            reserve_proofs,
            locked_xmr_buckets,
            withdrawal_hold_coverages,
            liquidity_exhaustion_blockers,
            reserve_refresh_requirements,
            process_feed_observations,
        }
    }

    pub fn reserve_proof_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-RESERVE-PROOF-ROOT",
            &records_from(
                self.reserve_proofs
                    .iter()
                    .map(ReserveProofObservation::public_record),
            ),
        )
    }

    pub fn locked_xmr_bucket_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-LOCKED-XMR-BUCKET-ROOT",
            &records_from(
                self.locked_xmr_buckets
                    .iter()
                    .map(LockedXmrBucket::public_record),
            ),
        )
    }

    pub fn withdrawal_hold_coverage_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-WITHDRAWAL-HOLD-COVERAGE-ROOT",
            &records_from(
                self.withdrawal_hold_coverages
                    .iter()
                    .map(WithdrawalHoldCoverage::public_record),
            ),
        )
    }

    pub fn liquidity_exhaustion_blocker_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-LIQUIDITY-EXHAUSTION-BLOCKER-ROOT",
            &records_from(
                self.liquidity_exhaustion_blockers
                    .iter()
                    .map(LiquidityExhaustionBlocker::public_record),
            ),
        )
    }

    pub fn reserve_refresh_requirement_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-RESERVE-REFRESH-REQUIREMENT-ROOT",
            &records_from(
                self.reserve_refresh_requirements
                    .iter()
                    .map(ReserveRefreshRequirement::public_record),
            ),
        )
    }

    pub fn process_feed_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-RESERVE-PROCESS-FEED-ROOT",
            &records_from(
                self.process_feed_observations
                    .iter()
                    .map(ProcessFeedObservation::public_record),
            ),
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-RESERVE-PROCESS-FEED-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.reserve_proof_root()),
                HashPart::Str(&self.locked_xmr_bucket_root()),
                HashPart::Str(&self.withdrawal_hold_coverage_root()),
                HashPart::Str(&self.liquidity_exhaustion_blocker_root()),
                HashPart::Str(&self.reserve_refresh_requirement_root()),
                HashPart::Str(&self.process_feed_root()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "reserve_proof_root": self.reserve_proof_root(),
            "locked_xmr_bucket_root": self.locked_xmr_bucket_root(),
            "withdrawal_hold_coverage_root": self.withdrawal_hold_coverage_root(),
            "liquidity_exhaustion_blocker_root": self.liquidity_exhaustion_blocker_root(),
            "reserve_refresh_requirement_root": self.reserve_refresh_requirement_root(),
            "process_feed_root": self.process_feed_root(),
            "state_root": self.state_root(),
            "reserve_proofs": records_from(self.reserve_proofs.iter().map(ReserveProofObservation::public_record)),
            "locked_xmr_buckets": records_from(self.locked_xmr_buckets.iter().map(LockedXmrBucket::public_record)),
            "withdrawal_hold_coverages": records_from(self.withdrawal_hold_coverages.iter().map(WithdrawalHoldCoverage::public_record)),
            "liquidity_exhaustion_blockers": records_from(self.liquidity_exhaustion_blockers.iter().map(LiquidityExhaustionBlocker::public_record)),
            "reserve_refresh_requirements": records_from(self.reserve_refresh_requirements.iter().map(ReserveRefreshRequirement::public_record)),
            "process_feed_observations": records_from(self.process_feed_observations.iter().map(ProcessFeedObservation::public_record)),
        })
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

pub fn record_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-RESERVE-PROCESS-FEED-RECORD",
        &[HashPart::Str(domain), HashPart::Json(payload)],
        32,
    )
}

fn reserve_proof_observation(
    observation_id: &str,
    process_feed_id: &str,
    locked_atomic_units: u64,
    pending_withdrawal_atomic_units: u64,
    liability_atomic_units: u64,
    observed_height: u64,
    proof_confirmations: u64,
    status: ReserveProofStatus,
) -> ReserveProofObservation {
    let coverage_bps = bps(locked_atomic_units, liability_atomic_units);
    ReserveProofObservation {
        observation_id: observation_id.to_string(),
        process_feed_id: process_feed_id.to_string(),
        reserve_root: deterministic_root("RESERVE-PROOF-RESERVE", observation_id),
        liability_root: deterministic_root("RESERVE-PROOF-LIABILITY", process_feed_id),
        observed_height,
        proof_confirmations,
        locked_atomic_units,
        pending_withdrawal_atomic_units,
        coverage_bps,
        status,
    }
}

fn locked_xmr_bucket(
    bucket_id: &str,
    kind: LockedXmrBucketKind,
    locked_atomic_units: u64,
    release_eligible_atomic_units: u64,
    holdback_atomic_units: u64,
    last_refresh_height: u64,
) -> LockedXmrBucket {
    LockedXmrBucket {
        bucket_id: bucket_id.to_string(),
        kind,
        custody_root: deterministic_root("LOCKED-XMR-BUCKET-CUSTODY", bucket_id),
        locked_atomic_units,
        release_eligible_atomic_units,
        holdback_atomic_units,
        last_refresh_height,
    }
}

fn withdrawal_hold_coverage(
    hold_id: &str,
    withdrawal_batch_id: &str,
    pending_atomic_units: u64,
    reserved_atomic_units: u64,
    release_after_height: u64,
    min_coverage_bps: u64,
) -> WithdrawalHoldCoverage {
    let coverage_bps = bps(reserved_atomic_units, pending_atomic_units);
    WithdrawalHoldCoverage {
        hold_id: hold_id.to_string(),
        withdrawal_batch_id: withdrawal_batch_id.to_string(),
        pending_atomic_units,
        reserved_atomic_units,
        coverage_bps,
        covered: coverage_bps >= min_coverage_bps,
        release_after_height,
    }
}

fn liquidity_exhaustion_blocker(
    blocker_id: &str,
    queue_id: &str,
    requested_atomic_units: u64,
    available_atomic_units: u64,
    exhaustion_blocker_bps: u64,
) -> LiquidityExhaustionBlocker {
    let utilization_bps = bps(requested_atomic_units, available_atomic_units);
    let status = if requested_atomic_units > available_atomic_units {
        BlockerStatus::Blocking
    } else if utilization_bps >= exhaustion_blocker_bps {
        BlockerStatus::Watch
    } else {
        BlockerStatus::Clear
    };
    LiquidityExhaustionBlocker {
        blocker_id: blocker_id.to_string(),
        queue_id: queue_id.to_string(),
        requested_atomic_units,
        available_atomic_units,
        utilization_bps,
        status,
        reason: blocker_reason(status).to_string(),
    }
}

fn reserve_refresh_requirement(
    requirement_id: &str,
    process_feed_id: &str,
    last_refresh_height: u64,
    current_height: u64,
    config: &Config,
) -> ReserveRefreshRequirement {
    let staleness_blocks = current_height.saturating_sub(last_refresh_height);
    let next_required_height = last_refresh_height + config.min_refresh_interval_blocks;
    let requirement = if staleness_blocks >= config.max_refresh_staleness_blocks {
        RefreshRequirement::Required
    } else if current_height >= next_required_height {
        RefreshRequirement::DueSoon
    } else {
        RefreshRequirement::Current
    };
    ReserveRefreshRequirement {
        requirement_id: requirement_id.to_string(),
        process_feed_id: process_feed_id.to_string(),
        last_refresh_height,
        current_height,
        next_required_height,
        staleness_blocks,
        requirement,
    }
}

fn process_feed_observations(
    reserve_proofs: &[ReserveProofObservation],
    locked_xmr_buckets: &[LockedXmrBucket],
    withdrawal_hold_coverages: &[WithdrawalHoldCoverage],
    liquidity_exhaustion_blockers: &[LiquidityExhaustionBlocker],
    reserve_refresh_requirements: &[ReserveRefreshRequirement],
) -> Vec<ProcessFeedObservation> {
    let mut sequence = 0_u64;
    let mut observations = Vec::new();
    for proof in reserve_proofs {
        sequence += 1;
        observations.push(process_feed_observation(
            ProcessFeedKind::ReserveProof,
            &proof.observation_id,
            &proof.state_root(),
            proof.observed_height,
            sequence,
        ));
    }
    for bucket in locked_xmr_buckets {
        sequence += 1;
        observations.push(process_feed_observation(
            ProcessFeedKind::LockedBucket,
            &bucket.bucket_id,
            &bucket.state_root(),
            bucket.last_refresh_height,
            sequence,
        ));
    }
    for hold in withdrawal_hold_coverages {
        sequence += 1;
        observations.push(process_feed_observation(
            ProcessFeedKind::WithdrawalHold,
            &hold.hold_id,
            &hold.state_root(),
            hold.release_after_height,
            sequence,
        ));
    }
    for blocker in liquidity_exhaustion_blockers {
        sequence += 1;
        observations.push(process_feed_observation(
            ProcessFeedKind::LiquidityBlocker,
            &blocker.blocker_id,
            &blocker.state_root(),
            1_033,
            sequence,
        ));
    }
    for requirement in reserve_refresh_requirements {
        sequence += 1;
        observations.push(process_feed_observation(
            ProcessFeedKind::ReserveRefresh,
            &requirement.requirement_id,
            &requirement.state_root(),
            requirement.current_height,
            sequence,
        ));
    }
    observations
}

fn process_feed_observation(
    kind: ProcessFeedKind,
    subject_id: &str,
    payload_root: &str,
    observed_height: u64,
    sequence: u64,
) -> ProcessFeedObservation {
    let feed_item_id = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-RESERVE-PROCESS-FEED-ITEM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::U64(sequence),
        ],
        32,
    );
    ProcessFeedObservation {
        feed_item_id,
        kind,
        subject_id: subject_id.to_string(),
        payload_root: payload_root.to_string(),
        observed_height,
        sequence,
    }
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)], 32)
}

fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(10_000) / denominator
    }
}

fn blocker_reason(status: BlockerStatus) -> &'static str {
    match status {
        BlockerStatus::Clear => "available_liquidity_covers_requested_escape_release",
        BlockerStatus::Watch => "requested_release_near_exhaustion_threshold",
        BlockerStatus::Blocking => "requested_release_exceeds_available_locked_xmr",
    }
}

fn records_from(records: impl Iterator<Item = Value>) -> Vec<Value> {
    records.collect()
}
