use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalLiquidityReserveSufficiencyReplayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_LIQUIDITY_RESERVE_SUFFICIENCY_REPLAY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-liquidity-reserve-sufficiency-replay-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_LIQUIDITY_RESERVE_SUFFICIENCY_REPLAY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const REPLAY_SUITE: &str =
    "canonical-forced-exit-liquidity-reserve-sufficiency-replay-fail-closed-v1";
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 = 12_000;
pub const DEFAULT_MIN_RELEASE_TRANCHE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_CHALLENGE_HOLDBACK_BPS: u64 = 1_200;
pub const DEFAULT_EMERGENCY_ROUTE_BPS: u64 = 2_000;
pub const DEFAULT_FEE_CAP_BPS: u64 = 8;
pub const DEFAULT_MAX_UTILIZATION_BPS: u64 = 8_500;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 5;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_REPLAY_ITEMS: usize = 256;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveLane {
    PrimaryForcedExit,
    CanonicalBackstop,
    ChallengeHoldback,
    EmergencyReserve,
}

impl ReserveLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrimaryForcedExit => "primary_forced_exit",
            Self::CanonicalBackstop => "canonical_backstop",
            Self::ChallengeHoldback => "challenge_holdback",
            Self::EmergencyReserve => "emergency_reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayCheckKind {
    ReserveRootBound,
    PendingLiabilityCovered,
    ChallengeHoldbackReserved,
    FeeCapRespected,
    LiquidityNotExhausted,
    ReleaseTrancheEligible,
    EmergencyReserveRouteAvailable,
    FailClosedReleaseRejected,
}

impl ReplayCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveRootBound => "reserve_root_bound",
            Self::PendingLiabilityCovered => "pending_liability_covered",
            Self::ChallengeHoldbackReserved => "challenge_holdback_reserved",
            Self::FeeCapRespected => "fee_cap_respected",
            Self::LiquidityNotExhausted => "liquidity_not_exhausted",
            Self::ReleaseTrancheEligible => "release_tranche_eligible",
            Self::EmergencyReserveRouteAvailable => "emergency_reserve_route_available",
            Self::FailClosedReleaseRejected => "fail_closed_release_rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Accepted,
    Watch,
    Rejected,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayOutcome {
    Sufficient,
    SufficientWithEmergencyRoute,
    Insufficient,
}

impl ReplayOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sufficient => "sufficient",
            Self::SufficientWithEmergencyRoute => "sufficient_with_emergency_route",
            Self::Insufficient => "insufficient",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    None,
    ReserveRootMissing,
    ReserveCoverageBelowFloor,
    ChallengeHoldbackBelowFloor,
    FeeAboveCap,
    LiquidityExhausted,
    TrancheNotEligible,
    EmergencyRouteUnavailable,
    AmbiguousReserveRelease,
}

impl RejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ReserveRootMissing => "reserve_root_missing",
            Self::ReserveCoverageBelowFloor => "reserve_coverage_below_floor",
            Self::ChallengeHoldbackBelowFloor => "challenge_holdback_below_floor",
            Self::FeeAboveCap => "fee_above_cap",
            Self::LiquidityExhausted => "liquidity_exhausted",
            Self::TrancheNotEligible => "tranche_not_eligible",
            Self::EmergencyRouteUnavailable => "emergency_route_unavailable",
            Self::AmbiguousReserveRelease => "ambiguous_reserve_release",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub replay_suite: String,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub min_release_tranche_coverage_bps: u64,
    pub challenge_holdback_bps: u64,
    pub emergency_route_bps: u64,
    pub fee_cap_bps: u64,
    pub max_utilization_bps: u64,
    pub min_pq_security_bits: u16,
    pub min_watcher_quorum: u64,
    pub min_privacy_set_size: u64,
    pub fail_closed_release_required: bool,
    pub production_release_allowed: bool,
    pub max_replay_items: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            replay_suite: REPLAY_SUITE.to_string(),
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps: DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            min_release_tranche_coverage_bps: DEFAULT_MIN_RELEASE_TRANCHE_COVERAGE_BPS,
            challenge_holdback_bps: DEFAULT_CHALLENGE_HOLDBACK_BPS,
            emergency_route_bps: DEFAULT_EMERGENCY_ROUTE_BPS,
            fee_cap_bps: DEFAULT_FEE_CAP_BPS,
            max_utilization_bps: DEFAULT_MAX_UTILIZATION_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            fail_closed_release_required: true,
            production_release_allowed: false,
            max_replay_items: DEFAULT_MAX_REPLAY_ITEMS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "replay_suite": self.replay_suite,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
            "min_release_tranche_coverage_bps": self.min_release_tranche_coverage_bps,
            "challenge_holdback_bps": self.challenge_holdback_bps,
            "emergency_route_bps": self.emergency_route_bps,
            "fee_cap_bps": self.fee_cap_bps,
            "max_utilization_bps": self.max_utilization_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_watcher_quorum": self.min_watcher_quorum,
            "min_privacy_set_size": self.min_privacy_set_size,
            "fail_closed_release_required": self.fail_closed_release_required,
            "production_release_allowed": self.production_release_allowed,
            "max_replay_items": self.max_replay_items,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveAccount {
    pub account_id: String,
    pub lane: ReserveLane,
    pub committed_atomic: u128,
    pub locked_atomic: u128,
    pub released_atomic: u128,
    pub attestation_root: String,
    pub pq_signer_root: String,
}

impl ReserveAccount {
    pub fn new(lane: ReserveLane, committed_atomic: u128, locked_atomic: u128, seed: &str) -> Self {
        let attestation_root = labeled_root("reserve-attestation", lane.as_str(), seed);
        let pq_signer_root = labeled_root("reserve-pq-signer", lane.as_str(), seed);
        let account_id = reserve_account_id(lane, &attestation_root, &pq_signer_root);
        Self {
            account_id,
            lane,
            committed_atomic,
            locked_atomic,
            released_atomic: 0,
            attestation_root,
            pq_signer_root,
        }
    }

    pub fn available_atomic(&self) -> u128 {
        self.committed_atomic.saturating_sub(self.locked_atomic)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "lane": self.lane.as_str(),
            "committed_atomic": self.committed_atomic,
            "locked_atomic": self.locked_atomic,
            "released_atomic": self.released_atomic,
            "available_atomic": self.available_atomic(),
            "attestation_root": self.attestation_root,
            "pq_signer_root": self.pq_signer_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reserve-account", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PendingExitLiability {
    pub exit_id: String,
    pub claimant_commitment: String,
    pub amount_atomic: u128,
    pub fee_bps: u64,
    pub challenge_holdback_atomic: u128,
    pub privacy_set_size: u64,
    pub watcher_quorum: u64,
    pub pq_security_bits: u16,
    pub claim_root: String,
}

impl PendingExitLiability {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        seed: &str,
        amount_atomic: u128,
        fee_bps: u64,
        holdback_bps: u64,
        privacy_set_size: u64,
        watcher_quorum: u64,
        pq_security_bits: u16,
    ) -> Self {
        let claimant_commitment = labeled_root("claimant", "forced-exit", seed);
        let claim_root = liability_claim_root(seed, &claimant_commitment, amount_atomic, fee_bps);
        let exit_id = liability_id(&claim_root, amount_atomic);
        Self {
            exit_id,
            claimant_commitment,
            amount_atomic,
            fee_bps,
            challenge_holdback_atomic: scale_amount(amount_atomic, holdback_bps),
            privacy_set_size,
            watcher_quorum,
            pq_security_bits,
            claim_root,
        }
    }

    pub fn total_required_atomic(&self) -> u128 {
        self.amount_atomic
            .saturating_add(self.challenge_holdback_atomic)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "exit_id": self.exit_id,
            "claimant_commitment": self.claimant_commitment,
            "amount_atomic": self.amount_atomic,
            "fee_bps": self.fee_bps,
            "challenge_holdback_atomic": self.challenge_holdback_atomic,
            "total_required_atomic": self.total_required_atomic(),
            "privacy_set_size": self.privacy_set_size,
            "watcher_quorum": self.watcher_quorum,
            "pq_security_bits": self.pq_security_bits,
            "claim_root": self.claim_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("pending-exit-liability", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseTranche {
    pub tranche_id: String,
    pub exit_id: String,
    pub account_id: String,
    pub lane: ReserveLane,
    pub amount_atomic: u128,
    pub eligible: bool,
    pub release_after_height: u64,
    pub evidence_root: String,
}

impl ReleaseTranche {
    pub fn public_record(&self) -> Value {
        json!({
            "tranche_id": self.tranche_id,
            "exit_id": self.exit_id,
            "account_id": self.account_id,
            "lane": self.lane.as_str(),
            "amount_atomic": self.amount_atomic,
            "eligible": self.eligible,
            "release_after_height": self.release_after_height,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release-tranche", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailClosedCase {
    pub case_id: String,
    pub exit_id: String,
    pub reason: RejectionReason,
    pub release_rejected: bool,
    pub observed_root: String,
}

impl FailClosedCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "exit_id": self.exit_id,
            "reason": self.reason.as_str(),
            "release_rejected": self.release_rejected,
            "observed_root": self.observed_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("fail-closed-case", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayCheck {
    pub check_id: String,
    pub exit_id: String,
    pub kind: ReplayCheckKind,
    pub status: CheckStatus,
    pub reason: RejectionReason,
    pub observed_root: String,
    pub note: String,
}

impl ReplayCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "exit_id": self.exit_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "reason": self.reason.as_str(),
            "observed_root": self.observed_root,
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("replay-check", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SufficiencyReport {
    pub report_id: String,
    pub outcome: ReplayOutcome,
    pub enough_reserve_to_honor_forced_exit: bool,
    pub reserve_root: String,
    pub pending_liability_root: String,
    pub challenge_holdback_root: String,
    pub release_tranche_root: String,
    pub fail_closed_case_root: String,
    pub check_root: String,
    pub total_pending_liability_atomic: u128,
    pub total_challenge_holdback_atomic: u128,
    pub total_required_atomic: u128,
    pub total_available_reserve_atomic: u128,
    pub emergency_available_atomic: u128,
    pub reserve_coverage_bps: u64,
    pub utilization_bps: u64,
    pub rejected_check_count: u64,
}

impl SufficiencyReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "outcome": self.outcome.as_str(),
            "enough_reserve_to_honor_forced_exit": self.enough_reserve_to_honor_forced_exit,
            "reserve_root": self.reserve_root,
            "pending_liability_root": self.pending_liability_root,
            "challenge_holdback_root": self.challenge_holdback_root,
            "release_tranche_root": self.release_tranche_root,
            "fail_closed_case_root": self.fail_closed_case_root,
            "check_root": self.check_root,
            "total_pending_liability_atomic": self.total_pending_liability_atomic,
            "total_challenge_holdback_atomic": self.total_challenge_holdback_atomic,
            "total_required_atomic": self.total_required_atomic,
            "total_available_reserve_atomic": self.total_available_reserve_atomic,
            "emergency_available_atomic": self.emergency_available_atomic,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "utilization_bps": self.utilization_bps,
            "rejected_check_count": self.rejected_check_count,
        })
    }

    pub fn state_root(&self) -> String {
        report_root(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub reserve_accounts: u64,
    pub pending_liabilities: u64,
    pub release_tranches: u64,
    pub fail_closed_cases: u64,
    pub checks: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reserve_accounts": self.reserve_accounts,
            "pending_liabilities": self.pending_liabilities,
            "release_tranches": self.release_tranches,
            "fail_closed_cases": self.fail_closed_cases,
            "checks": self.checks,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub reserve_accounts: Vec<ReserveAccount>,
    pub pending_liabilities: Vec<PendingExitLiability>,
    pub release_tranches: Vec<ReleaseTranche>,
    pub fail_closed_cases: Vec<FailClosedCase>,
    pub checks: Vec<ReplayCheck>,
    pub latest_report: SufficiencyReport,
    pub counters: Counters,
    pub metadata: BTreeMap<String, String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let empty = SufficiencyReport {
            report_id: report_id(&merkle_root("EMPTY-SUFFICIENCY-REPORT", &[])),
            outcome: ReplayOutcome::Insufficient,
            enough_reserve_to_honor_forced_exit: false,
            reserve_root: merkle_root("EMPTY-RESERVE-ROOT", &[]),
            pending_liability_root: merkle_root("EMPTY-PENDING-LIABILITY-ROOT", &[]),
            challenge_holdback_root: merkle_root("EMPTY-CHALLENGE-HOLDBACK-ROOT", &[]),
            release_tranche_root: merkle_root("EMPTY-RELEASE-TRANCHE-ROOT", &[]),
            fail_closed_case_root: merkle_root("EMPTY-FAIL-CLOSED-CASE-ROOT", &[]),
            check_root: merkle_root("EMPTY-SUFFICIENCY-CHECK-ROOT", &[]),
            total_pending_liability_atomic: 0,
            total_challenge_holdback_atomic: 0,
            total_required_atomic: 0,
            total_available_reserve_atomic: 0,
            emergency_available_atomic: 0,
            reserve_coverage_bps: 0,
            utilization_bps: 0,
            rejected_check_count: 0,
        };
        Self {
            config,
            reserve_accounts: Vec::new(),
            pending_liabilities: Vec::new(),
            release_tranches: Vec::new(),
            fail_closed_cases: Vec::new(),
            checks: Vec::new(),
            latest_report: empty,
            counters: Counters::default(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config);
        state.reserve_accounts = vec![
            ReserveAccount::new(
                ReserveLane::PrimaryForcedExit,
                9_000_000_000_000,
                250_000_000_000,
                "devnet-primary",
            ),
            ReserveAccount::new(
                ReserveLane::CanonicalBackstop,
                2_000_000_000_000,
                100_000_000_000,
                "devnet-backstop",
            ),
            ReserveAccount::new(
                ReserveLane::ChallengeHoldback,
                900_000_000_000,
                40_000_000_000,
                "devnet-holdback",
            ),
            ReserveAccount::new(
                ReserveLane::EmergencyReserve,
                1_500_000_000_000,
                0,
                "devnet-emergency",
            ),
        ];
        state.pending_liabilities = vec![
            PendingExitLiability::new(
                "devnet-exit-alpha",
                4_000_000_000_000,
                5,
                state.config.challenge_holdback_bps,
                98_304,
                7,
                256,
            ),
            PendingExitLiability::new(
                "devnet-exit-beta",
                2_500_000_000_000,
                6,
                state.config.challenge_holdback_bps,
                131_072,
                6,
                256,
            ),
        ];
        state.metadata.insert(
            "answer".to_string(),
            "reserve_liquidity_is_sufficient_for_the_devnet_forced_exit_set".to_string(),
        );
        state.replay();
        state
    }

    pub fn replay(&mut self) {
        self.release_tranches = build_release_tranches(
            &self.config,
            &self.reserve_accounts,
            &self.pending_liabilities,
        );
        self.fail_closed_cases = build_fail_closed_cases(&self.pending_liabilities);
        self.checks = build_checks(
            &self.config,
            &self.reserve_accounts,
            &self.pending_liabilities,
            &self.release_tranches,
            &self.fail_closed_cases,
        );
        self.counters = Counters {
            reserve_accounts: self.reserve_accounts.len() as u64,
            pending_liabilities: self.pending_liabilities.len() as u64,
            release_tranches: self.release_tranches.len() as u64,
            fail_closed_cases: self.fail_closed_cases.len() as u64,
            checks: self.checks.len() as u64,
        };
        self.latest_report = build_report(
            &self.reserve_accounts,
            &self.pending_liabilities,
            &self.release_tranches,
            &self.fail_closed_cases,
            &self.checks,
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "reserve_accounts": self.reserve_accounts.iter().map(ReserveAccount::public_record).collect::<Vec<_>>(),
            "pending_liabilities": self.pending_liabilities.iter().map(PendingExitLiability::public_record).collect::<Vec<_>>(),
            "release_tranches": self.release_tranches.iter().map(ReleaseTranche::public_record).collect::<Vec<_>>(),
            "fail_closed_cases": self.fail_closed_cases.iter().map(FailClosedCase::public_record).collect::<Vec<_>>(),
            "checks": self.checks.iter().map(ReplayCheck::public_record).collect::<Vec<_>>(),
            "latest_report": self.latest_report.public_record(),
            "counters": self.counters.public_record(),
            "metadata": self.metadata,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-RESERVE-SUFFICIENCY-REPLAY-STATE",
            &[
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.latest_report.state_root()),
                HashPart::Str(&record_root("counters", &self.counters.public_record())),
                HashPart::Str(&record_root("metadata", &json!(self.metadata))),
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

fn build_release_tranches(
    config: &Config,
    reserves: &[ReserveAccount],
    liabilities: &[PendingExitLiability],
) -> Vec<ReleaseTranche> {
    let primary = reserves
        .iter()
        .find(|reserve| reserve.lane == ReserveLane::PrimaryForcedExit);
    let holdback = reserves
        .iter()
        .find(|reserve| reserve.lane == ReserveLane::ChallengeHoldback);

    liabilities
        .iter()
        .flat_map(|liability| {
            let primary_tranche = primary.map(|account| {
                make_tranche(
                    liability,
                    account,
                    liability.amount_atomic,
                    account.available_atomic() >= liability.amount_atomic
                        && liability.fee_bps <= config.fee_cap_bps,
                    4_260_420,
                    "primary",
                )
            });
            let holdback_tranche = holdback.map(|account| {
                make_tranche(
                    liability,
                    account,
                    liability.challenge_holdback_atomic,
                    account.available_atomic() >= liability.challenge_holdback_atomic,
                    4_260_456,
                    "challenge-holdback",
                )
            });
            primary_tranche
                .into_iter()
                .chain(holdback_tranche)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn build_fail_closed_cases(liabilities: &[PendingExitLiability]) -> Vec<FailClosedCase> {
    liabilities
        .iter()
        .map(|liability| {
            let observed_root = domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-FAIL-CLOSED-OBSERVED",
                &[
                    HashPart::Str(&liability.exit_id),
                    HashPart::Str(RejectionReason::AmbiguousReserveRelease.as_str()),
                    HashPart::Str("release-without-sufficient-canonical-proof"),
                ],
                32,
            );
            let case_id = fail_closed_case_id(&liability.exit_id, &observed_root);
            FailClosedCase {
                case_id,
                exit_id: liability.exit_id.clone(),
                reason: RejectionReason::AmbiguousReserveRelease,
                release_rejected: true,
                observed_root,
            }
        })
        .collect()
}

fn build_checks(
    config: &Config,
    reserves: &[ReserveAccount],
    liabilities: &[PendingExitLiability],
    tranches: &[ReleaseTranche],
    fail_closed_cases: &[FailClosedCase],
) -> Vec<ReplayCheck> {
    let reserve_records = reserves
        .iter()
        .map(ReserveAccount::public_record)
        .collect::<Vec<_>>();
    let reserve_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-RESERVE-ROOT",
        &reserve_records,
    );
    let total_required = liabilities
        .iter()
        .map(PendingExitLiability::total_required_atomic)
        .sum::<u128>();
    let total_holdback = liabilities
        .iter()
        .map(|liability| liability.challenge_holdback_atomic)
        .sum::<u128>();
    let total_available = reserves
        .iter()
        .map(ReserveAccount::available_atomic)
        .sum::<u128>();
    let emergency_available = reserves
        .iter()
        .filter(|reserve| reserve.lane == ReserveLane::EmergencyReserve)
        .map(ReserveAccount::available_atomic)
        .sum::<u128>();
    let reserve_coverage_bps = bps(total_available, total_required);
    let holdback_available = reserves
        .iter()
        .filter(|reserve| reserve.lane == ReserveLane::ChallengeHoldback)
        .map(ReserveAccount::available_atomic)
        .sum::<u128>();
    let release_tranche_coverage_bps = bps(
        tranches
            .iter()
            .filter(|tranche| tranche.eligible)
            .map(|tranche| tranche.amount_atomic)
            .sum::<u128>(),
        total_required,
    );
    let worst_fee_bps = liabilities
        .iter()
        .map(|liability| liability.fee_bps)
        .max()
        .unwrap_or(0);
    let utilization_bps = bps(total_required, total_available);
    let all_tranches_eligible = tranches.iter().all(|tranche| tranche.eligible);
    let fail_closed_rejected = fail_closed_cases.iter().all(|case| case.release_rejected);
    let emergency_required = total_available < total_required
        || reserve_coverage_bps < config.target_reserve_coverage_bps;
    let emergency_sufficient = !emergency_required
        || emergency_available >= scale_amount(total_required, config.emergency_route_bps);

    vec![
        make_check(
            "aggregate",
            ReplayCheckKind::ReserveRootBound,
            !reserve_root.is_empty(),
            reserve_root,
            RejectionReason::ReserveRootMissing,
            "canonical reserve root is bound into the replay",
        ),
        make_check(
            "aggregate",
            ReplayCheckKind::PendingLiabilityCovered,
            reserve_coverage_bps >= config.min_reserve_coverage_bps,
            record_root("pending-liability-total", &json!(total_required)),
            RejectionReason::ReserveCoverageBelowFloor,
            "available reserve covers pending forced-exit liabilities",
        ),
        make_check(
            "aggregate",
            ReplayCheckKind::ChallengeHoldbackReserved,
            holdback_available >= total_holdback,
            record_root("challenge-holdback-total", &json!(total_holdback)),
            RejectionReason::ChallengeHoldbackBelowFloor,
            "challenge holdbacks are reserved before release",
        ),
        make_check(
            "aggregate",
            ReplayCheckKind::FeeCapRespected,
            worst_fee_bps <= config.fee_cap_bps,
            record_root("fee-cap", &json!(worst_fee_bps)),
            RejectionReason::FeeAboveCap,
            "forced-exit release fee stays within the cap",
        ),
        make_check(
            "aggregate",
            ReplayCheckKind::LiquidityNotExhausted,
            utilization_bps <= config.max_utilization_bps,
            record_root("utilization", &json!(utilization_bps)),
            RejectionReason::LiquidityExhausted,
            "reserve utilization stays below exhaustion threshold",
        ),
        make_check(
            "aggregate",
            ReplayCheckKind::ReleaseTrancheEligible,
            all_tranches_eligible
                && release_tranche_coverage_bps >= config.min_release_tranche_coverage_bps,
            record_root(
                "release-tranche-coverage",
                &json!(release_tranche_coverage_bps),
            ),
            RejectionReason::TrancheNotEligible,
            "all canonical release tranches are eligible",
        ),
        make_check(
            "aggregate",
            ReplayCheckKind::EmergencyReserveRouteAvailable,
            emergency_sufficient,
            record_root("emergency-available", &json!(emergency_available)),
            RejectionReason::EmergencyRouteUnavailable,
            "emergency reserve route can absorb a shortfall",
        ),
        make_check(
            "aggregate",
            ReplayCheckKind::FailClosedReleaseRejected,
            !config.fail_closed_release_required || fail_closed_rejected,
            record_root("fail-closed-cases", &json!(fail_closed_cases.len())),
            RejectionReason::AmbiguousReserveRelease,
            "ambiguous reserve releases are rejected fail-closed",
        ),
    ]
}

fn build_report(
    reserves: &[ReserveAccount],
    liabilities: &[PendingExitLiability],
    tranches: &[ReleaseTranche],
    fail_closed_cases: &[FailClosedCase],
    checks: &[ReplayCheck],
) -> SufficiencyReport {
    let reserve_records = reserves
        .iter()
        .map(ReserveAccount::public_record)
        .collect::<Vec<_>>();
    let liability_records = liabilities
        .iter()
        .map(PendingExitLiability::public_record)
        .collect::<Vec<_>>();
    let holdback_records = liabilities
        .iter()
        .map(|liability| {
            json!({
                "exit_id": liability.exit_id,
                "challenge_holdback_atomic": liability.challenge_holdback_atomic,
            })
        })
        .collect::<Vec<_>>();
    let tranche_records = tranches
        .iter()
        .map(ReleaseTranche::public_record)
        .collect::<Vec<_>>();
    let fail_closed_records = fail_closed_cases
        .iter()
        .map(FailClosedCase::public_record)
        .collect::<Vec<_>>();
    let check_records = checks
        .iter()
        .map(ReplayCheck::public_record)
        .collect::<Vec<_>>();
    let reserve_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-RESERVE-ROOT",
        &reserve_records,
    );
    let pending_liability_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-PENDING-LIABILITIES",
        &liability_records,
    );
    let challenge_holdback_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-CHALLENGE-HOLDBACKS",
        &holdback_records,
    );
    let release_tranche_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-RELEASE-TRANCHES",
        &tranche_records,
    );
    let fail_closed_case_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-FAIL-CLOSED-CASES",
        &fail_closed_records,
    );
    let check_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-SUFFICIENCY-CHECKS",
        &check_records,
    );
    let total_pending_liability_atomic = liabilities
        .iter()
        .map(|liability| liability.amount_atomic)
        .sum::<u128>();
    let total_challenge_holdback_atomic = liabilities
        .iter()
        .map(|liability| liability.challenge_holdback_atomic)
        .sum::<u128>();
    let total_required_atomic =
        total_pending_liability_atomic.saturating_add(total_challenge_holdback_atomic);
    let total_available_reserve_atomic = reserves
        .iter()
        .map(ReserveAccount::available_atomic)
        .sum::<u128>();
    let emergency_available_atomic = reserves
        .iter()
        .filter(|reserve| reserve.lane == ReserveLane::EmergencyReserve)
        .map(ReserveAccount::available_atomic)
        .sum::<u128>();
    let reserve_coverage_bps = bps(total_available_reserve_atomic, total_required_atomic);
    let utilization_bps = bps(total_required_atomic, total_available_reserve_atomic);
    let rejected_check_count = checks
        .iter()
        .filter(|check| check.status == CheckStatus::Rejected)
        .count() as u64;
    let emergency_check_rejected = checks.iter().any(|check| {
        check.kind == ReplayCheckKind::EmergencyReserveRouteAvailable
            && check.status == CheckStatus::Rejected
    });
    let enough_reserve_to_honor_forced_exit =
        rejected_check_count == 0 && total_available_reserve_atomic >= total_required_atomic;
    let outcome = if enough_reserve_to_honor_forced_exit && emergency_check_rejected {
        ReplayOutcome::SufficientWithEmergencyRoute
    } else if enough_reserve_to_honor_forced_exit {
        ReplayOutcome::Sufficient
    } else {
        ReplayOutcome::Insufficient
    };
    let report_body = json!({
        "outcome": outcome.as_str(),
        "reserve_root": reserve_root,
        "pending_liability_root": pending_liability_root,
        "challenge_holdback_root": challenge_holdback_root,
        "release_tranche_root": release_tranche_root,
        "fail_closed_case_root": fail_closed_case_root,
        "check_root": check_root,
        "total_required_atomic": total_required_atomic,
        "total_available_reserve_atomic": total_available_reserve_atomic,
    });
    let root = report_root(&report_body);

    SufficiencyReport {
        report_id: report_id(&root),
        outcome,
        enough_reserve_to_honor_forced_exit,
        reserve_root,
        pending_liability_root,
        challenge_holdback_root,
        release_tranche_root,
        fail_closed_case_root,
        check_root,
        total_pending_liability_atomic,
        total_challenge_holdback_atomic,
        total_required_atomic,
        total_available_reserve_atomic,
        emergency_available_atomic,
        reserve_coverage_bps,
        utilization_bps,
        rejected_check_count,
    }
}

fn make_tranche(
    liability: &PendingExitLiability,
    account: &ReserveAccount,
    amount_atomic: u128,
    eligible: bool,
    release_after_height: u64,
    label: &str,
) -> ReleaseTranche {
    let evidence_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-RELEASE-TRANCHE-EVIDENCE",
        &[
            HashPart::Str(&liability.exit_id),
            HashPart::Str(&account.account_id),
            HashPart::Str(label),
            HashPart::U64((amount_atomic & u64::MAX as u128) as u64),
            HashPart::Str(if eligible { "eligible" } else { "blocked" }),
        ],
        32,
    );
    let tranche_id = release_tranche_id(&liability.exit_id, &account.account_id, &evidence_root);
    ReleaseTranche {
        tranche_id,
        exit_id: liability.exit_id.clone(),
        account_id: account.account_id.clone(),
        lane: account.lane,
        amount_atomic,
        eligible,
        release_after_height,
        evidence_root,
    }
}

fn make_check(
    exit_id: &str,
    kind: ReplayCheckKind,
    accepted: bool,
    observed_root: String,
    reason: RejectionReason,
    note: &str,
) -> ReplayCheck {
    let status = if accepted {
        CheckStatus::Accepted
    } else {
        CheckStatus::Rejected
    };
    let reason = if accepted {
        RejectionReason::None
    } else {
        reason
    };
    let check_id = replay_check_id(exit_id, kind, &observed_root);
    ReplayCheck {
        check_id,
        exit_id: exit_id.to_string(),
        kind,
        status,
        reason,
        observed_root,
        note: note.to_string(),
    }
}

fn scale_amount(amount: u128, bps_value: u64) -> u128 {
    amount
        .saturating_mul(bps_value as u128)
        .saturating_add((MAX_BPS - 1) as u128)
        / MAX_BPS as u128
}

fn bps(numerator: u128, denominator: u128) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(MAX_BPS as u128)
        .checked_div(denominator)
        .unwrap_or(0)
        .min(u64::MAX as u128) as u64
}

pub fn reserve_account_id(
    lane: ReserveLane,
    attestation_root: &str,
    pq_signer_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-RESERVE-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(attestation_root),
            HashPart::Str(pq_signer_root),
        ],
        32,
    )
}

pub fn liability_claim_root(
    seed: &str,
    claimant_commitment: &str,
    amount_atomic: u128,
    fee_bps: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-LIABILITY-CLAIM-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(seed),
            HashPart::Str(claimant_commitment),
            HashPart::U64((amount_atomic & u64::MAX as u128) as u64),
            HashPart::U64(fee_bps),
        ],
        32,
    )
}

pub fn liability_id(claim_root: &str, amount_atomic: u128) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-LIABILITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(claim_root),
            HashPart::U64((amount_atomic & u64::MAX as u128) as u64),
        ],
        32,
    )
}

pub fn release_tranche_id(exit_id: &str, account_id: &str, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-RELEASE-TRANCHE-ID",
        &[
            HashPart::Str(exit_id),
            HashPart::Str(account_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn fail_closed_case_id(exit_id: &str, observed_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-FAIL-CLOSED-CASE-ID",
        &[HashPart::Str(exit_id), HashPart::Str(observed_root)],
        32,
    )
}

pub fn replay_check_id(exit_id: &str, kind: ReplayCheckKind, observed_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-SUFFICIENCY-CHECK-ID",
        &[
            HashPart::Str(exit_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(observed_root),
        ],
        32,
    )
}

pub fn report_root(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-SUFFICIENCY-REPORT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn report_id(report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-SUFFICIENCY-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(report_root),
        ],
        32,
    )
}

pub fn labeled_root(label: &str, scope: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-LABELED-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(scope),
            HashPart::Str(seed),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LIQUIDITY-SUFFICIENCY-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
