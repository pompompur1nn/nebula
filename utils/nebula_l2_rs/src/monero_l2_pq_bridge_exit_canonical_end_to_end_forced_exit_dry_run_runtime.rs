use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalEndToEndForcedExitDryRunRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_END_TO_END_FORCED_EXIT_DRY_RUN_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-end-to-end-forced-exit-dry-run-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_END_TO_END_FORCED_EXIT_DRY_RUN_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DRY_RUN_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-end-to-end-forced-exit-dry-run-v1";
pub const DEFAULT_L2_HEIGHT: u64 = 4_240_000;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_520_000;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_FEE_ATOMIC: u64 = 35_000_000;
pub const DEFAULT_MIN_PQ_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MAX_PUBLIC_METADATA_FIELDS: u64 = 3;
pub const DEFAULT_MIN_WALLET_RECOVERY_SHARDS: u64 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DryRunLeg {
    DepositLock,
    PrivateNoteMint,
    PrivateTransferReceipt,
    ContractActionReceipt,
    SettlementReceipt,
    WithdrawalClaim,
    ChallengeWindow,
    AdversarialRecovery,
    RuntimeEvidenceAcceptance,
    ProductionReleaseDecision,
}

impl DryRunLeg {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::PrivateNoteMint => "private_note_mint",
            Self::PrivateTransferReceipt => "private_transfer_receipt",
            Self::ContractActionReceipt => "contract_action_receipt",
            Self::SettlementReceipt => "settlement_receipt",
            Self::WithdrawalClaim => "withdrawal_claim",
            Self::ChallengeWindow => "challenge_window",
            Self::AdversarialRecovery => "adversarial_recovery",
            Self::RuntimeEvidenceAcceptance => "runtime_evidence_acceptance",
            Self::ProductionReleaseDecision => "production_release_decision",
        }
    }

    pub fn ordinal(self) -> u64 {
        match self {
            Self::DepositLock => 0,
            Self::PrivateNoteMint => 1,
            Self::PrivateTransferReceipt => 2,
            Self::ContractActionReceipt => 3,
            Self::SettlementReceipt => 4,
            Self::WithdrawalClaim => 5,
            Self::ChallengeWindow => 6,
            Self::AdversarialRecovery => 7,
            Self::RuntimeEvidenceAcceptance => 8,
            Self::ProductionReleaseDecision => 9,
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::DepositLock,
            Self::PrivateNoteMint,
            Self::PrivateTransferReceipt,
            Self::ContractActionReceipt,
            Self::SettlementReceipt,
            Self::WithdrawalClaim,
            Self::ChallengeWindow,
            Self::AdversarialRecovery,
            Self::RuntimeEvidenceAcceptance,
            Self::ProductionReleaseDecision,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DryRunStatus {
    Accepted,
    Watch,
    Deferred,
    ReleaseHold,
}

impl DryRunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Deferred => "deferred",
            Self::ReleaseHold => "release_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DryRunBlocker {
    LiveFeedStub,
    CargoRuntimeDeferred,
    IndependentAuditOpen,
    ProductionReleaseHold,
}

impl DryRunBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiveFeedStub => "live_feed_stub",
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::IndependentAuditOpen => "independent_audit_open",
            Self::ProductionReleaseHold => "production_release_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DryRunVerdict {
    ForcedExitPathProvedByDeterministicRecords,
    ProductionReleaseBlocked,
}

impl DryRunVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForcedExitPathProvedByDeterministicRecords => {
                "forced_exit_path_proved_by_deterministic_records"
            }
            Self::ProductionReleaseBlocked => "production_release_blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub challenge_window_blocks: u64,
    pub max_fee_atomic: u64,
    pub min_pq_weight_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_public_metadata_fields: u64,
    pub min_wallet_recovery_shards: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            l2_network: "nebula-devnet".to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_reference_height: DEFAULT_L2_HEIGHT,
            monero_reference_height: DEFAULT_MONERO_HEIGHT,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_fee_atomic: DEFAULT_MAX_FEE_ATOMIC,
            min_pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            max_public_metadata_fields: DEFAULT_MAX_PUBLIC_METADATA_FIELDS,
            min_wallet_recovery_shards: DEFAULT_MIN_WALLET_RECOVERY_SHARDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "dry_run_suite": DRY_RUN_SUITE,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "challenge_window_blocks": self.challenge_window_blocks,
            "max_fee_atomic": self.max_fee_atomic,
            "min_pq_weight_bps": self.min_pq_weight_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_public_metadata_fields": self.max_public_metadata_fields,
            "min_wallet_recovery_shards": self.min_wallet_recovery_shards,
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
pub struct LegEvidence {
    pub leg: DryRunLeg,
    pub status: DryRunStatus,
    pub evidence_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_wallet_root: String,
    pub pq_authority_root: String,
    pub reserve_root: String,
    pub privacy_root: String,
    pub fail_closed_root: String,
    pub operator_cooperation_required: bool,
    pub wallet_can_reconstruct: bool,
    pub fee_atomic: u64,
    pub public_metadata_fields: u64,
    pub pq_weight_bps: u64,
    pub reserve_coverage_bps: u64,
    pub blocker: Option<DryRunBlocker>,
}

impl LegEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "leg": self.leg.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_wallet_root": self.encrypted_wallet_root,
            "pq_authority_root": self.pq_authority_root,
            "reserve_root": self.reserve_root,
            "privacy_root": self.privacy_root,
            "fail_closed_root": self.fail_closed_root,
            "operator_cooperation_required": yes_no(self.operator_cooperation_required),
            "wallet_can_reconstruct": yes_no(self.wallet_can_reconstruct),
            "fee_atomic": self.fee_atomic,
            "public_metadata_fields": self.public_metadata_fields,
            "pq_weight_bps": self.pq_weight_bps,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "blocker": self.blocker.map(DryRunBlocker::as_str).unwrap_or("none"),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(self.leg.as_str(), &self.public_record())
    }

    pub fn is_accepted(&self) -> bool {
        self.status == DryRunStatus::Accepted
            || self.status == DryRunStatus::Watch
            || self.status == DryRunStatus::ReleaseHold
    }

    pub fn is_production_blocker(&self) -> bool {
        matches!(
            self.blocker,
            Some(
                DryRunBlocker::CargoRuntimeDeferred
                    | DryRunBlocker::IndependentAuditOpen
                    | DryRunBlocker::ProductionReleaseHold
            )
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DryRunCounters {
    pub total_legs: u64,
    pub accepted_legs: u64,
    pub watch_legs: u64,
    pub deferred_legs: u64,
    pub production_blockers: u64,
    pub operator_dependent_legs: u64,
    pub wallet_reconstructable_legs: u64,
    pub max_fee_atomic: u64,
    pub max_public_metadata_fields: u64,
    pub min_pq_weight_bps: u64,
    pub min_reserve_coverage_bps: u64,
}

impl DryRunCounters {
    pub fn from_evidence(evidence: &[LegEvidence]) -> Self {
        let total_legs = evidence.len() as u64;
        let accepted_legs = evidence.iter().filter(|leg| leg.is_accepted()).count() as u64;
        let watch_legs = evidence
            .iter()
            .filter(|leg| leg.status == DryRunStatus::Watch)
            .count() as u64;
        let deferred_legs = evidence
            .iter()
            .filter(|leg| leg.status == DryRunStatus::Deferred)
            .count() as u64;
        let production_blockers = evidence
            .iter()
            .filter(|leg| leg.is_production_blocker())
            .count() as u64;
        let operator_dependent_legs = evidence
            .iter()
            .filter(|leg| leg.operator_cooperation_required)
            .count() as u64;
        let wallet_reconstructable_legs = evidence
            .iter()
            .filter(|leg| leg.wallet_can_reconstruct)
            .count() as u64;
        let max_fee_atomic = evidence
            .iter()
            .map(|leg| leg.fee_atomic)
            .max()
            .unwrap_or_default();
        let max_public_metadata_fields = evidence
            .iter()
            .map(|leg| leg.public_metadata_fields)
            .max()
            .unwrap_or_default();
        let min_pq_weight_bps = evidence
            .iter()
            .map(|leg| leg.pq_weight_bps)
            .min()
            .unwrap_or_default();
        let min_reserve_coverage_bps = evidence
            .iter()
            .map(|leg| leg.reserve_coverage_bps)
            .min()
            .unwrap_or_default();

        Self {
            total_legs,
            accepted_legs,
            watch_legs,
            deferred_legs,
            production_blockers,
            operator_dependent_legs,
            wallet_reconstructable_legs,
            max_fee_atomic,
            max_public_metadata_fields,
            min_pq_weight_bps,
            min_reserve_coverage_bps,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_legs": self.total_legs,
            "accepted_legs": self.accepted_legs,
            "watch_legs": self.watch_legs,
            "deferred_legs": self.deferred_legs,
            "production_blockers": self.production_blockers,
            "operator_dependent_legs": self.operator_dependent_legs,
            "wallet_reconstructable_legs": self.wallet_reconstructable_legs,
            "max_fee_atomic": self.max_fee_atomic,
            "max_public_metadata_fields": self.max_public_metadata_fields,
            "min_pq_weight_bps": self.min_pq_weight_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("dry_run_counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DryRunRoots {
    pub leg_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_wallet_root: String,
    pub pq_authority_root: String,
    pub reserve_root: String,
    pub privacy_root: String,
    pub fail_closed_root: String,
    pub counter_root: String,
    pub acceptance_root: String,
}

impl DryRunRoots {
    pub fn from_evidence(evidence: &[LegEvidence], counters: &DryRunCounters) -> Self {
        let leg_records = evidence
            .iter()
            .map(LegEvidence::public_record)
            .collect::<Vec<_>>();
        let public_records = evidence
            .iter()
            .map(|leg| json!({ "leg": leg.leg.as_str(), "root": leg.public_root }))
            .collect::<Vec<_>>();
        let committed_records = evidence
            .iter()
            .map(|leg| json!({ "leg": leg.leg.as_str(), "root": leg.committed_root }))
            .collect::<Vec<_>>();
        let encrypted_records = evidence
            .iter()
            .map(|leg| json!({ "leg": leg.leg.as_str(), "root": leg.encrypted_wallet_root }))
            .collect::<Vec<_>>();
        let pq_records = evidence
            .iter()
            .map(|leg| json!({ "leg": leg.leg.as_str(), "root": leg.pq_authority_root }))
            .collect::<Vec<_>>();
        let reserve_records = evidence
            .iter()
            .map(|leg| json!({ "leg": leg.leg.as_str(), "root": leg.reserve_root }))
            .collect::<Vec<_>>();
        let privacy_records = evidence
            .iter()
            .map(|leg| json!({ "leg": leg.leg.as_str(), "root": leg.privacy_root }))
            .collect::<Vec<_>>();
        let fail_closed_records = evidence
            .iter()
            .map(|leg| json!({ "leg": leg.leg.as_str(), "root": leg.fail_closed_root }))
            .collect::<Vec<_>>();
        let acceptance_records = evidence
            .iter()
            .map(|leg| {
                json!({
                    "leg": leg.leg.as_str(),
                    "status": leg.status.as_str(),
                    "blocker": leg.blocker.map(DryRunBlocker::as_str).unwrap_or("none"),
                })
            })
            .collect::<Vec<_>>();

        Self {
            leg_root: merkle_root(
                "monero-l2-pq-bridge-exit-forced-exit-dry-run-legs",
                &leg_records,
            ),
            public_root: merkle_root(
                "monero-l2-pq-bridge-exit-forced-exit-dry-run-public",
                &public_records,
            ),
            committed_root: merkle_root(
                "monero-l2-pq-bridge-exit-forced-exit-dry-run-committed",
                &committed_records,
            ),
            encrypted_wallet_root: merkle_root(
                "monero-l2-pq-bridge-exit-forced-exit-dry-run-wallet",
                &encrypted_records,
            ),
            pq_authority_root: merkle_root(
                "monero-l2-pq-bridge-exit-forced-exit-dry-run-pq",
                &pq_records,
            ),
            reserve_root: merkle_root(
                "monero-l2-pq-bridge-exit-forced-exit-dry-run-reserve",
                &reserve_records,
            ),
            privacy_root: merkle_root(
                "monero-l2-pq-bridge-exit-forced-exit-dry-run-privacy",
                &privacy_records,
            ),
            fail_closed_root: merkle_root(
                "monero-l2-pq-bridge-exit-forced-exit-dry-run-fail-closed",
                &fail_closed_records,
            ),
            counter_root: counters.state_root(),
            acceptance_root: merkle_root(
                "monero-l2-pq-bridge-exit-forced-exit-dry-run-acceptance",
                &acceptance_records,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "leg_root": self.leg_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_wallet_root": self.encrypted_wallet_root,
            "pq_authority_root": self.pq_authority_root,
            "reserve_root": self.reserve_root,
            "privacy_root": self.privacy_root,
            "fail_closed_root": self.fail_closed_root,
            "counter_root": self.counter_root,
            "acceptance_root": self.acceptance_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("dry_run_roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndToEndDryRun {
    pub dry_run_id: String,
    pub operator_independent_exit: bool,
    pub wallet_local_reconstruction: bool,
    pub live_handlers_executed: bool,
    pub cargo_runtime_executed: bool,
    pub production_release_allowed: bool,
    pub verdict: DryRunVerdict,
    pub counters: DryRunCounters,
    pub roots: DryRunRoots,
}

impl EndToEndDryRun {
    pub fn public_record(&self) -> Value {
        json!({
            "dry_run_id": self.dry_run_id,
            "operator_independent_exit": yes_no(self.operator_independent_exit),
            "wallet_local_reconstruction": yes_no(self.wallet_local_reconstruction),
            "live_handlers_executed": yes_no(self.live_handlers_executed),
            "cargo_runtime_executed": yes_no(self.cargo_runtime_executed),
            "production_release_allowed": yes_no(self.production_release_allowed),
            "verdict": self.verdict.as_str(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("end_to_end_dry_run", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub evidence: Vec<LegEvidence>,
    pub dry_run: EndToEndDryRun,
    pub blocker_notes: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let evidence = devnet_evidence(&config);
        let counters = DryRunCounters::from_evidence(&evidence);
        let roots = DryRunRoots::from_evidence(&evidence, &counters);
        let blocker_notes = blocker_notes();
        let dry_run = EndToEndDryRun {
            dry_run_id: dry_run_id(&config, &roots),
            operator_independent_exit: counters.operator_dependent_legs == 0,
            wallet_local_reconstruction: counters.wallet_reconstructable_legs
                == counters.total_legs,
            live_handlers_executed: false,
            cargo_runtime_executed: false,
            production_release_allowed: false,
            verdict: DryRunVerdict::ProductionReleaseBlocked,
            counters,
            roots,
        };

        Self {
            config,
            evidence,
            dry_run,
            blocker_notes,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "evidence": self.evidence.iter().map(LegEvidence::public_record).collect::<Vec<_>>(),
            "dry_run": self.dry_run.public_record(),
            "blocker_notes": self.blocker_notes,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-end-to-end-forced-exit-dry-run-state",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.dry_run.state_root()),
                HashPart::Str(&blocker_note_root(&self.blocker_notes)),
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

pub fn state_root_from_value(value: &Value) -> String {
    record_root("external_value", value)
}

fn devnet_evidence(config: &Config) -> Vec<LegEvidence> {
    DryRunLeg::all()
        .into_iter()
        .map(|leg| leg_evidence(config, leg))
        .collect()
}

fn leg_evidence(config: &Config, leg: DryRunLeg) -> LegEvidence {
    let status = match leg {
        DryRunLeg::ChallengeWindow => DryRunStatus::Watch,
        DryRunLeg::RuntimeEvidenceAcceptance => DryRunStatus::Deferred,
        DryRunLeg::ProductionReleaseDecision => DryRunStatus::ReleaseHold,
        _ => DryRunStatus::Accepted,
    };
    let blocker = match leg {
        DryRunLeg::SettlementReceipt => Some(DryRunBlocker::LiveFeedStub),
        DryRunLeg::RuntimeEvidenceAcceptance => Some(DryRunBlocker::CargoRuntimeDeferred),
        DryRunLeg::ProductionReleaseDecision => Some(DryRunBlocker::ProductionReleaseHold),
        DryRunLeg::AdversarialRecovery => Some(DryRunBlocker::IndependentAuditOpen),
        _ => None,
    };
    let payload = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "leg": leg.as_str(),
        "ordinal": leg.ordinal(),
        "l2_reference_height": config.l2_reference_height + leg.ordinal(),
        "monero_reference_height": config.monero_reference_height + leg.ordinal(),
        "operator_metadata": "redacted",
        "wallet_material": "encrypted",
        "blocker": blocker.map(DryRunBlocker::as_str).unwrap_or("none"),
    });

    LegEvidence {
        leg,
        status,
        evidence_root: domain_hash(
            "monero-l2-pq-bridge-exit-forced-exit-dry-run-evidence",
            &[HashPart::Json(&payload)],
            32,
        ),
        public_root: lane_root("public", leg, &payload),
        committed_root: lane_root("committed", leg, &payload),
        encrypted_wallet_root: lane_root("encrypted-wallet", leg, &payload),
        pq_authority_root: lane_root("pq-authority", leg, &payload),
        reserve_root: lane_root("reserve", leg, &payload),
        privacy_root: lane_root("privacy", leg, &payload),
        fail_closed_root: lane_root("fail-closed", leg, &payload),
        operator_cooperation_required: false,
        wallet_can_reconstruct: true,
        fee_atomic: config.max_fee_atomic / 2 + leg.ordinal(),
        public_metadata_fields: match leg {
            DryRunLeg::ProductionReleaseDecision => 1,
            DryRunLeg::RuntimeEvidenceAcceptance => 2,
            _ => 0,
        },
        pq_weight_bps: config.min_pq_weight_bps + 700,
        reserve_coverage_bps: config.min_reserve_coverage_bps + 1_200,
        blocker,
    }
}

fn lane_root(lane: &str, leg: DryRunLeg, payload: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-forced-exit-dry-run-lane",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane),
            HashPart::Str(leg.as_str()),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn dry_run_id(config: &Config, roots: &DryRunRoots) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-forced-exit-dry-run-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::Str(&roots.leg_root),
            HashPart::Str(&roots.acceptance_root),
        ],
        16,
    )
}

fn blocker_notes() -> BTreeMap<String, String> {
    [
        (
            "cargo_runtime_deferred",
            "dry-run records are deterministic, but cargo/runtime execution is still deferred by workflow",
        ),
        (
            "live_feed_stub",
            "settlement receipt leg remains stub-backed until live Monero and reserve feeds are connected",
        ),
        (
            "independent_audit_open",
            "adversarial recovery evidence needs independent bridge, privacy, and PQ review",
        ),
        (
            "production_release_hold",
            "production release remains blocked until real forced-exit execution succeeds",
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

fn blocker_note_root(notes: &BTreeMap<String, String>) -> String {
    let records = notes
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-forced-exit-dry-run-blocker-notes",
        &records,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-forced-exit-dry-run-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
