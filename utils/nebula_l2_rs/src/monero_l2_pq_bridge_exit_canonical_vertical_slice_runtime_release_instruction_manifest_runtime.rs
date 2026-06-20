use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};
use crate::CHAIN_ID;

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceRuntimeReleaseInstructionManifestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_RELEASE_INSTRUCTION_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-release-instruction-manifest-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_RELEASE_INSTRUCTION_MANIFEST_RUNTIME_PROTOCOL_VERSION;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReleaseInstructionLane {
    ExitAcceptance,
    WalletInstruction,
    MoneroTransactionPlan,
    PqCustodyAuthorization,
    LiquidityExecution,
    ChallengeDispute,
    PrivacyBoundary,
    LiveFeedObservation,
    ReleaseBlocker,
}

impl ReleaseInstructionLane {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExitAcceptance => "exit_acceptance",
            Self::WalletInstruction => "wallet_instruction",
            Self::MoneroTransactionPlan => "monero_transaction_plan",
            Self::PqCustodyAuthorization => "pq_custody_authorization",
            Self::LiquidityExecution => "liquidity_execution",
            Self::ChallengeDispute => "challenge_dispute",
            Self::PrivacyBoundary => "privacy_boundary",
            Self::LiveFeedObservation => "live_feed_observation",
            Self::ReleaseBlocker => "release_blocker",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::ExitAcceptance => "Exit acceptance",
            Self::WalletInstruction => "Wallet instruction",
            Self::MoneroTransactionPlan => "Monero transaction plan",
            Self::PqCustodyAuthorization => "PQ custody authorization",
            Self::LiquidityExecution => "Liquidity execution",
            Self::ChallengeDispute => "Challenge dispute",
            Self::PrivacyBoundary => "Privacy boundary",
            Self::LiveFeedObservation => "Live feed observation",
            Self::ReleaseBlocker => "Release blocker",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReleaseInstructionStatus {
    Issue,
    Queue,
    Watch,
    Hold,
}

impl ReleaseInstructionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Queue => "queue",
            Self::Watch => "watch",
            Self::Hold => "hold",
        }
    }

    pub fn blocks_release(&self) -> bool {
        !matches!(self, Self::Issue)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReleaseInstructionVerdict {
    IssueInstruction,
    QueueInstruction,
    HoldInstruction,
}

impl ReleaseInstructionVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IssueInstruction => "issue_instruction",
            Self::QueueInstruction => "queue_instruction",
            Self::HoldInstruction => "hold_instruction",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub custody_epoch: u64,
    pub release_queue_height: u64,
    pub challenge_window_end_height: u64,
    pub min_pq_quorum_bps: u64,
    pub min_liquidity_coverage_bps: u64,
    pub max_fee_bps: u64,
    pub max_metadata_units: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_reference_height: 1_049_120,
            monero_reference_height: 3_241_260,
            custody_epoch: 84,
            release_queue_height: 1_049_168,
            challenge_window_end_height: 1_049_164,
            min_pq_quorum_bps: 6_700,
            min_liquidity_coverage_bps: 10_500,
            max_fee_bps: 120,
            max_metadata_units: 12,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_instruction_config",
            "chain_id": self.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "custody_epoch": self.custody_epoch,
            "release_queue_height": self.release_queue_height,
            "challenge_window_end_height": self.challenge_window_end_height,
            "min_pq_quorum_bps": self.min_pq_quorum_bps,
            "min_liquidity_coverage_bps": self.min_liquidity_coverage_bps,
            "max_fee_bps": self.max_fee_bps,
            "max_metadata_units": self.max_metadata_units,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-config",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseInstructionRequirement {
    pub lane: ReleaseInstructionLane,
    pub requirement_id: String,
    pub required_root: String,
    pub required_weight_bps: u64,
    pub issue_critical: bool,
    pub instruction_kind: String,
    pub description: String,
}

impl ReleaseInstructionRequirement {
    pub fn new(
        config: &Config,
        lane: ReleaseInstructionLane,
        instruction_kind: &str,
        required_weight_bps: u64,
        issue_critical: bool,
        description: &str,
    ) -> Self {
        let required_root = required_instruction_root(config, &lane, instruction_kind);
        let requirement_id = domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-requirement-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(lane.as_str()),
                HashPart::Str(instruction_kind),
                HashPart::Str(&required_root),
                HashPart::U64(required_weight_bps),
            ],
            16,
        );
        Self {
            lane,
            requirement_id,
            required_root,
            required_weight_bps,
            issue_critical,
            instruction_kind: instruction_kind.to_string(),
            description: description.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_instruction_requirement",
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "requirement_id": self.requirement_id,
            "required_root": self.required_root,
            "required_weight_bps": self.required_weight_bps,
            "issue_critical": self.issue_critical,
            "instruction_kind": self.instruction_kind,
            "description": self.description,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-requirement",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseInstructionRecord {
    pub lane: ReleaseInstructionLane,
    pub instruction_id: String,
    pub requirement_id: String,
    pub expected_root: String,
    pub supplied_root: String,
    pub status: ReleaseInstructionStatus,
    pub issue_weight_bps: u64,
    pub fee_cap_bps: u64,
    pub hold_count: u64,
    pub redacted_instruction_root: String,
}

impl ReleaseInstructionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_instruction_record",
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "instruction_id": self.instruction_id,
            "requirement_id": self.requirement_id,
            "expected_root": self.expected_root,
            "supplied_root": self.supplied_root,
            "status": self.status.as_str(),
            "issue_weight_bps": self.issue_weight_bps,
            "fee_cap_bps": self.fee_cap_bps,
            "hold_count": self.hold_count,
            "redacted_instruction_root": self.redacted_instruction_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-record",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseInstructionHold {
    pub lane: ReleaseInstructionLane,
    pub hold_id: String,
    pub requirement_id: String,
    pub hold_code: String,
    pub severity_bps: u64,
    pub expected_root: String,
    pub supplied_root: String,
    pub hold_reason: String,
}

impl ReleaseInstructionHold {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_instruction_hold",
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "hold_id": self.hold_id,
            "requirement_id": self.requirement_id,
            "hold_code": self.hold_code,
            "severity_bps": self.severity_bps,
            "expected_root": self.expected_root,
            "supplied_root": self.supplied_root,
            "hold_reason": self.hold_reason,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-hold",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseInstructionCounters {
    pub requirement_count: u64,
    pub record_count: u64,
    pub issue_count: u64,
    pub queue_count: u64,
    pub watch_count: u64,
    pub hold_count: u64,
    pub blocker_count: u64,
    pub critical_hold_count: u64,
}

impl ReleaseInstructionCounters {
    pub fn from_records(
        requirements: &[ReleaseInstructionRequirement],
        records: &[ReleaseInstructionRecord],
        holds: &[ReleaseInstructionHold],
    ) -> Self {
        let issue_count = records
            .iter()
            .filter(|record| record.status == ReleaseInstructionStatus::Issue)
            .count() as u64;
        let queue_count = records
            .iter()
            .filter(|record| record.status == ReleaseInstructionStatus::Queue)
            .count() as u64;
        let watch_count = records
            .iter()
            .filter(|record| record.status == ReleaseInstructionStatus::Watch)
            .count() as u64;
        let hold_count = records
            .iter()
            .filter(|record| record.status == ReleaseInstructionStatus::Hold)
            .count() as u64;
        let blocker_count = records.iter().map(|record| record.hold_count).sum::<u64>();
        let critical_hold_count = requirements
            .iter()
            .filter(|requirement| {
                requirement.issue_critical
                    && records.iter().any(|record| {
                        record.requirement_id == requirement.requirement_id
                            && record.status.blocks_release()
                    })
            })
            .count() as u64;
        Self {
            requirement_count: requirements.len() as u64,
            record_count: records.len() as u64,
            issue_count,
            queue_count,
            watch_count,
            hold_count,
            blocker_count: blocker_count + holds.len() as u64,
            critical_hold_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_instruction_counters",
            "requirement_count": self.requirement_count,
            "record_count": self.record_count,
            "issue_count": self.issue_count,
            "queue_count": self.queue_count,
            "watch_count": self.watch_count,
            "hold_count": self.hold_count,
            "blocker_count": self.blocker_count,
            "critical_hold_count": self.critical_hold_count,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-counters",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseInstructionRoots {
    pub config_root: String,
    pub requirement_root: String,
    pub record_root: String,
    pub hold_root: String,
    pub lane_status_root: String,
    pub redacted_payload_root: String,
    pub release_instruction_root: String,
    pub manifest_id: String,
}

impl ReleaseInstructionRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_instruction_roots",
            "config_root": self.config_root,
            "requirement_root": self.requirement_root,
            "record_root": self.record_root,
            "hold_root": self.hold_root,
            "lane_status_root": self.lane_status_root,
            "redacted_payload_root": self.redacted_payload_root,
            "release_instruction_root": self.release_instruction_root,
            "manifest_id": self.manifest_id,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-roots",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseInstructionManifest {
    pub manifest_id: String,
    pub verdict: ReleaseInstructionVerdict,
    pub counters: ReleaseInstructionCounters,
    pub roots: ReleaseInstructionRoots,
    pub release_holds: BTreeMap<String, String>,
}

impl ReleaseInstructionManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_instruction_manifest",
            "manifest_id": self.manifest_id,
            "verdict": self.verdict.as_str(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "release_holds": self.release_holds,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-manifest",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub requirements: Vec<ReleaseInstructionRequirement>,
    pub records: Vec<ReleaseInstructionRecord>,
    pub holds: Vec<ReleaseInstructionHold>,
    pub manifest: ReleaseInstructionManifest,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let requirements = release_instruction_requirements(&config);
        let records = release_instruction_records(&config, &requirements);
        let holds = hold_records(&requirements, &records);
        let counters = ReleaseInstructionCounters::from_records(&requirements, &records, &holds);
        let release_holds = release_hold_map(&requirements, &records, &holds);
        let roots = release_instruction_roots(&config, &requirements, &records, &holds);
        let verdict = manifest_verdict(&counters);
        let manifest = ReleaseInstructionManifest {
            manifest_id: roots.manifest_id.clone(),
            verdict,
            counters,
            roots,
            release_holds,
        };
        Self {
            config,
            requirements,
            records,
            holds,
            manifest,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_instruction_manifest_state",
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "requirements": self
                .requirements
                .iter()
                .map(ReleaseInstructionRequirement::public_record)
                .collect::<Vec<_>>(),
            "records": self
                .records
                .iter()
                .map(ReleaseInstructionRecord::public_record)
                .collect::<Vec<_>>(),
            "holds": self
                .holds
                .iter()
                .map(ReleaseInstructionHold::public_record)
                .collect::<Vec<_>>(),
            "manifest": self.manifest.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-state",
            &[HashPart::Json(&self.public_record())],
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

fn release_instruction_requirements(config: &Config) -> Vec<ReleaseInstructionRequirement> {
    vec![
        ReleaseInstructionRequirement::new(
            config,
            ReleaseInstructionLane::ExitAcceptance,
            "accepted_exit_evidence_and_hold_surface",
            9_500,
            true,
            "Exit acceptance roots must authorize instruction issuance or explicitly hold release.",
        ),
        ReleaseInstructionRequirement::new(
            config,
            ReleaseInstructionLane::WalletInstruction,
            "wallet_release_payload_and_encrypted_notice",
            9_000,
            true,
            "Wallet release payload must bind destination commitments, claim receipts, and user-visible hold reasons.",
        ),
        ReleaseInstructionRequirement::new(
            config,
            ReleaseInstructionLane::MoneroTransactionPlan,
            "monero_release_transaction_plan_root",
            9_000,
            true,
            "Monero release plan must bind custody outputs, payout commitments, fee caps, decoy policy, and receipt roots.",
        ),
        ReleaseInstructionRequirement::new(
            config,
            ReleaseInstructionLane::PqCustodyAuthorization,
            "pq_custody_release_authorization_root",
            config.min_pq_quorum_bps,
            true,
            "PQ custody authorization must bind signer quorum, watcher attestations, key epochs, and signature domains.",
        ),
        ReleaseInstructionRequirement::new(
            config,
            ReleaseInstructionLane::LiquidityExecution,
            "liquidity_release_execution_root",
            config.min_liquidity_coverage_bps,
            true,
            "Liquidity execution must prove reserve coverage, queue priority, fee caps, and settlement receipt roots.",
        ),
        ReleaseInstructionRequirement::new(
            config,
            ReleaseInstructionLane::ChallengeDispute,
            "challenge_window_closed_or_timeout_root",
            9_000,
            true,
            "Challenge and dispute windows must be closed or timeout evidence must be accepted before release.",
        ),
        ReleaseInstructionRequirement::new(
            config,
            ReleaseInstructionLane::PrivacyBoundary,
            "privacy_preserving_release_payload_root",
            9_000,
            true,
            "Release instruction must preserve privacy budgets and avoid leaking wallet metadata.",
        ),
        ReleaseInstructionRequirement::new(
            config,
            ReleaseInstructionLane::LiveFeedObservation,
            "live_feed_release_observation_root",
            8_500,
            true,
            "Live Monero and watcher observations must match release instruction evidence before custody moves.",
        ),
        ReleaseInstructionRequirement::new(
            config,
            ReleaseInstructionLane::ReleaseBlocker,
            "release_blocker_instruction_clearance_root",
            10_000,
            true,
            "All release blockers must be cleared before a custody release instruction is issued.",
        ),
    ]
}

fn release_instruction_records(
    config: &Config,
    requirements: &[ReleaseInstructionRequirement],
) -> Vec<ReleaseInstructionRecord> {
    requirements
        .iter()
        .map(|requirement| {
            let supplied_root = supplied_instruction_root(config, requirement);
            let status = status_for(requirement, &supplied_root);
            let hold_count = hold_count_for(requirement, &status, &supplied_root);
            let redacted_instruction_root =
                redacted_instruction_root(config, requirement, &supplied_root, &status);
            let instruction_id = domain_hash(
                "monero-l2-pq-bridge-exit-release-instruction-id",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(requirement.lane.as_str()),
                    HashPart::Str(&requirement.requirement_id),
                    HashPart::Str(&supplied_root),
                    HashPart::Str(status.as_str()),
                ],
                16,
            );
            ReleaseInstructionRecord {
                lane: requirement.lane.clone(),
                instruction_id,
                requirement_id: requirement.requirement_id.clone(),
                expected_root: requirement.required_root.clone(),
                supplied_root,
                status,
                issue_weight_bps: issue_weight_for(requirement),
                fee_cap_bps: fee_cap_for(requirement, config),
                hold_count,
                redacted_instruction_root,
            }
        })
        .collect()
}

fn required_instruction_root(
    config: &Config,
    lane: &ReleaseInstructionLane,
    instruction_kind: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-release-instruction-required-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(instruction_kind),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::U64(config.custody_epoch),
            HashPart::U64(config.release_queue_height),
        ],
        32,
    )
}

fn supplied_instruction_root(
    config: &Config,
    requirement: &ReleaseInstructionRequirement,
) -> String {
    match requirement.lane {
        ReleaseInstructionLane::ExitAcceptance
        | ReleaseInstructionLane::WalletInstruction
        | ReleaseInstructionLane::PqCustodyAuthorization
        | ReleaseInstructionLane::PrivacyBoundary => requirement.required_root.clone(),
        ReleaseInstructionLane::MoneroTransactionPlan => domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-supplied-monero-plan",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&requirement.requirement_id),
                HashPart::U64(config.max_fee_bps + 15),
            ],
            32,
        ),
        ReleaseInstructionLane::LiquidityExecution => domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-supplied-liquidity",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&requirement.requirement_id),
                HashPart::U64(config.min_liquidity_coverage_bps - 250),
            ],
            32,
        ),
        ReleaseInstructionLane::ChallengeDispute => domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-supplied-challenge",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&requirement.requirement_id),
                HashPart::U64(config.challenge_window_end_height - 4),
            ],
            32,
        ),
        ReleaseInstructionLane::LiveFeedObservation => domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-supplied-live-feed",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&requirement.requirement_id),
                HashPart::U64(config.monero_reference_height),
            ],
            32,
        ),
        ReleaseInstructionLane::ReleaseBlocker => domain_hash(
            "monero-l2-pq-bridge-exit-release-instruction-supplied-blocker",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&requirement.requirement_id),
                HashPart::Str("cargo-runtime-and-audit-hold-open"),
            ],
            32,
        ),
    }
}

fn status_for(
    requirement: &ReleaseInstructionRequirement,
    supplied_root: &str,
) -> ReleaseInstructionStatus {
    if supplied_root == requirement.required_root && requirement.required_weight_bps >= 9_000 {
        ReleaseInstructionStatus::Issue
    } else if supplied_root == requirement.required_root {
        ReleaseInstructionStatus::Queue
    } else {
        match requirement.lane {
            ReleaseInstructionLane::MoneroTransactionPlan
            | ReleaseInstructionLane::LiveFeedObservation
            | ReleaseInstructionLane::ReleaseBlocker => ReleaseInstructionStatus::Hold,
            ReleaseInstructionLane::LiquidityExecution
            | ReleaseInstructionLane::ChallengeDispute => ReleaseInstructionStatus::Watch,
            _ => ReleaseInstructionStatus::Queue,
        }
    }
}

fn issue_weight_for(requirement: &ReleaseInstructionRequirement) -> u64 {
    match requirement.lane {
        ReleaseInstructionLane::ExitAcceptance => 9_700,
        ReleaseInstructionLane::WalletInstruction => 9_300,
        ReleaseInstructionLane::MoneroTransactionPlan => 8_100,
        ReleaseInstructionLane::PqCustodyAuthorization => 7_400,
        ReleaseInstructionLane::LiquidityExecution => 10_100,
        ReleaseInstructionLane::ChallengeDispute => 8_700,
        ReleaseInstructionLane::PrivacyBoundary => 9_200,
        ReleaseInstructionLane::LiveFeedObservation => 7_900,
        ReleaseInstructionLane::ReleaseBlocker => 6_500,
    }
}

fn fee_cap_for(requirement: &ReleaseInstructionRequirement, config: &Config) -> u64 {
    match requirement.lane {
        ReleaseInstructionLane::MoneroTransactionPlan => config.max_fee_bps,
        ReleaseInstructionLane::LiquidityExecution => config.max_fee_bps + 20,
        ReleaseInstructionLane::WalletInstruction => config.max_fee_bps + 10,
        _ => config.max_fee_bps,
    }
}

fn hold_count_for(
    requirement: &ReleaseInstructionRequirement,
    status: &ReleaseInstructionStatus,
    supplied_root: &str,
) -> u64 {
    let root_hold = if supplied_root == requirement.required_root {
        0
    } else {
        1
    };
    let status_hold = match status {
        ReleaseInstructionStatus::Issue => 0,
        ReleaseInstructionStatus::Queue => {
            if requirement.issue_critical {
                1
            } else {
                0
            }
        }
        ReleaseInstructionStatus::Watch => 1,
        ReleaseInstructionStatus::Hold => 2,
    };
    root_hold + status_hold
}

fn redacted_instruction_root(
    config: &Config,
    requirement: &ReleaseInstructionRequirement,
    supplied_root: &str,
    status: &ReleaseInstructionStatus,
) -> String {
    let payload = json!({
        "lane": requirement.lane.as_str(),
        "requirement_id": requirement.requirement_id,
        "supplied_root": supplied_root,
        "status": status.as_str(),
        "l2_reference_height": config.l2_reference_height,
        "custody_epoch": config.custody_epoch,
        "release_queue_height": config.release_queue_height,
        "public_fields_only": ["lane", "status", "roots", "heights"],
    });
    domain_hash(
        "monero-l2-pq-bridge-exit-release-instruction-redacted-payload",
        &[HashPart::Json(&payload)],
        32,
    )
}

fn hold_records(
    requirements: &[ReleaseInstructionRequirement],
    records: &[ReleaseInstructionRecord],
) -> Vec<ReleaseInstructionHold> {
    requirements
        .iter()
        .filter_map(|requirement| {
            records
                .iter()
                .find(|record| record.requirement_id == requirement.requirement_id)
                .filter(|record| record.status.blocks_release() || record.hold_count > 0)
                .map(|record| {
                    let hold_code = hold_code_for(requirement, record);
                    let hold_reason = hold_reason_for(requirement, record);
                    let hold_id = domain_hash(
                        "monero-l2-pq-bridge-exit-release-instruction-hold-id",
                        &[
                            HashPart::Str(CHAIN_ID),
                            HashPart::Str(PROTOCOL_VERSION),
                            HashPart::Str(requirement.lane.as_str()),
                            HashPart::Str(&requirement.requirement_id),
                            HashPart::Str(&record.supplied_root),
                            HashPart::Str(&hold_code),
                        ],
                        16,
                    );
                    ReleaseInstructionHold {
                        lane: requirement.lane.clone(),
                        hold_id,
                        requirement_id: requirement.requirement_id.clone(),
                        hold_code,
                        severity_bps: hold_severity(requirement, record),
                        expected_root: record.expected_root.clone(),
                        supplied_root: record.supplied_root.clone(),
                        hold_reason,
                    }
                })
        })
        .collect()
}

fn hold_code_for(
    requirement: &ReleaseInstructionRequirement,
    record: &ReleaseInstructionRecord,
) -> String {
    if record.expected_root != record.supplied_root {
        format!("{}_instruction_root_mismatch", requirement.lane.as_str())
    } else if record.status.blocks_release() {
        format!("{}_instruction_status_hold", requirement.lane.as_str())
    } else {
        format!("{}_instruction_queued", requirement.lane.as_str())
    }
}

fn hold_reason_for(
    requirement: &ReleaseInstructionRequirement,
    record: &ReleaseInstructionRecord,
) -> String {
    match requirement.lane {
        ReleaseInstructionLane::ExitAcceptance => {
            "exit acceptance must authorize issuance before custody release instruction is formed"
                .to_string()
        }
        ReleaseInstructionLane::WalletInstruction => {
            "wallet-facing payload must bind destination commitments and encrypted notice roots"
                .to_string()
        }
        ReleaseInstructionLane::MoneroTransactionPlan => {
            "Monero release transaction plan requires matching fee, decoy, and receipt roots"
                .to_string()
        }
        ReleaseInstructionLane::PqCustodyAuthorization => {
            "PQ custody authorization must bind quorum, key epoch, and withdrawal authority roots"
                .to_string()
        }
        ReleaseInstructionLane::LiquidityExecution => {
            "liquidity execution must clear reserve coverage and queue-priority holds".to_string()
        }
        ReleaseInstructionLane::ChallengeDispute => {
            "challenge and dispute windows must be closed before release instruction issuance"
                .to_string()
        }
        ReleaseInstructionLane::PrivacyBoundary => {
            "release instruction payload must remain within committed privacy disclosure bounds"
                .to_string()
        }
        ReleaseInstructionLane::LiveFeedObservation => {
            "live Monero and watcher observation roots must be exercised by the runtime harness"
                .to_string()
        }
        ReleaseInstructionLane::ReleaseBlocker => format!(
            "release blocker remains {} for custody instruction issuance",
            record.status.as_str()
        ),
    }
}

fn hold_severity(
    requirement: &ReleaseInstructionRequirement,
    record: &ReleaseInstructionRecord,
) -> u64 {
    let root_penalty = if record.expected_root == record.supplied_root {
        0
    } else {
        3_000
    };
    let status_penalty = match record.status {
        ReleaseInstructionStatus::Issue => 0,
        ReleaseInstructionStatus::Queue => 1_000,
        ReleaseInstructionStatus::Watch => 1_500,
        ReleaseInstructionStatus::Hold => 4_000,
    };
    let critical_penalty = if requirement.issue_critical { 1_000 } else { 0 };
    (root_penalty + status_penalty + critical_penalty).min(10_000)
}

fn release_instruction_roots(
    config: &Config,
    requirements: &[ReleaseInstructionRequirement],
    records: &[ReleaseInstructionRecord],
    holds: &[ReleaseInstructionHold],
) -> ReleaseInstructionRoots {
    let config_root = config.state_root();
    let requirement_root = requirement_root(requirements);
    let record_root = record_root(records);
    let hold_root = hold_root(holds);
    let lane_status_root = lane_status_root(records);
    let redacted_payload_root = redacted_payload_root(records);
    let release_instruction_root = domain_hash(
        "monero-l2-pq-bridge-exit-release-instruction-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config_root),
            HashPart::Str(&requirement_root),
            HashPart::Str(&record_root),
            HashPart::Str(&hold_root),
            HashPart::Str(&lane_status_root),
            HashPart::Str(&redacted_payload_root),
        ],
        32,
    );
    let manifest_id = domain_hash(
        "monero-l2-pq-bridge-exit-release-instruction-manifest-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::U64(config.custody_epoch),
            HashPart::Str(&release_instruction_root),
            HashPart::Str(&hold_root),
        ],
        16,
    );
    ReleaseInstructionRoots {
        config_root,
        requirement_root,
        record_root,
        hold_root,
        lane_status_root,
        redacted_payload_root,
        release_instruction_root,
        manifest_id,
    }
}

fn requirement_root(requirements: &[ReleaseInstructionRequirement]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-release-instruction-requirements",
        &requirements
            .iter()
            .map(ReleaseInstructionRequirement::public_record)
            .collect::<Vec<_>>(),
    )
}

fn record_root(records: &[ReleaseInstructionRecord]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-release-instruction-records",
        &records
            .iter()
            .map(ReleaseInstructionRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

fn hold_root(holds: &[ReleaseInstructionHold]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-release-instruction-holds",
        &holds
            .iter()
            .map(ReleaseInstructionHold::public_record)
            .collect::<Vec<_>>(),
    )
}

fn lane_status_root(records: &[ReleaseInstructionRecord]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            json!({
                "lane": record.lane.as_str(),
                "status": record.status.as_str(),
                "hold_count": record.hold_count,
                "instruction_root": record.state_root(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-release-instruction-lane-status",
        &leaves,
    )
}

fn redacted_payload_root(records: &[ReleaseInstructionRecord]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-release-instruction-redacted-payloads",
        &records
            .iter()
            .map(|record| {
                json!({
                    "lane": record.lane.as_str(),
                    "status": record.status.as_str(),
                    "redacted_instruction_root": record.redacted_instruction_root,
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn release_hold_map(
    requirements: &[ReleaseInstructionRequirement],
    records: &[ReleaseInstructionRecord],
    holds: &[ReleaseInstructionHold],
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(
        "runtime_execution".to_string(),
        "release instruction roots still require cargo/runtime execution before custody moves"
            .to_string(),
    );
    map.insert(
        "audit_review".to_string(),
        "custody release instruction issuance remains audit-held until live key and reserve review"
            .to_string(),
    );
    for hold in holds {
        map.insert(
            format!("hold_{}", hold.lane.as_str()),
            hold.hold_reason.clone(),
        );
    }
    for requirement in requirements {
        if let Some(record) = records
            .iter()
            .find(|item| item.requirement_id == requirement.requirement_id)
        {
            if record.status.blocks_release() {
                map.insert(
                    format!("lane_{}", requirement.lane.as_str()),
                    hold_reason_for(requirement, record),
                );
            }
        }
    }
    map
}

fn manifest_verdict(counters: &ReleaseInstructionCounters) -> ReleaseInstructionVerdict {
    if counters.critical_hold_count == 0 && counters.hold_count == 0 && counters.blocker_count == 0
    {
        ReleaseInstructionVerdict::IssueInstruction
    } else if counters.hold_count == 0 {
        ReleaseInstructionVerdict::QueueInstruction
    } else {
        ReleaseInstructionVerdict::HoldInstruction
    }
}
