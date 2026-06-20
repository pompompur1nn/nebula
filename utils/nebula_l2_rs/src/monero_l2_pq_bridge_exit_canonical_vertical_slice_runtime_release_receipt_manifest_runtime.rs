use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};
use crate::CHAIN_ID;

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceRuntimeReleaseReceiptManifestRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_RELEASE_RECEIPT_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-release-receipt-manifest-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_RELEASE_RECEIPT_MANIFEST_RUNTIME_PROTOCOL_VERSION;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReleaseReceiptLane {
    ReleaseInstruction,
    WalletReceipt,
    MoneroBroadcast,
    PqCustodySignature,
    LiquiditySettlement,
    ReorgWatch,
    PrivacyBoundary,
    AdversarialReceipt,
    ReleaseBlocker,
}

impl ReleaseReceiptLane {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReleaseInstruction => "release_instruction",
            Self::WalletReceipt => "wallet_receipt",
            Self::MoneroBroadcast => "monero_broadcast",
            Self::PqCustodySignature => "pq_custody_signature",
            Self::LiquiditySettlement => "liquidity_settlement",
            Self::ReorgWatch => "reorg_watch",
            Self::PrivacyBoundary => "privacy_boundary",
            Self::AdversarialReceipt => "adversarial_receipt",
            Self::ReleaseBlocker => "release_blocker",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::ReleaseInstruction => "Release instruction",
            Self::WalletReceipt => "Wallet receipt",
            Self::MoneroBroadcast => "Monero broadcast",
            Self::PqCustodySignature => "PQ custody signature",
            Self::LiquiditySettlement => "Liquidity settlement",
            Self::ReorgWatch => "Reorg watch",
            Self::PrivacyBoundary => "Privacy boundary",
            Self::AdversarialReceipt => "Adversarial receipt",
            Self::ReleaseBlocker => "Release blocker",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReleaseReceiptStatus {
    Accepted,
    Pending,
    Watch,
    Blocked,
}

impl ReleaseReceiptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Pending => "pending",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }

    pub fn blocks_acceptance(&self) -> bool {
        !matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReleaseReceiptVerdict {
    AcceptReceipt,
    HoldReceipt,
    RejectReceipt,
}

impl ReleaseReceiptVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AcceptReceipt => "accept_receipt",
            Self::HoldReceipt => "hold_receipt",
            Self::RejectReceipt => "reject_receipt",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub release_instruction_height: u64,
    pub broadcast_observation_height: u64,
    pub confirmation_target_height: u64,
    pub reorg_watch_depth: u64,
    pub min_pq_quorum_bps: u64,
    pub min_liquidity_settlement_bps: u64,
    pub max_metadata_units: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_reference_height: 1_049_760,
            monero_reference_height: 3_241_332,
            release_instruction_height: 1_049_168,
            broadcast_observation_height: 3_241_348,
            confirmation_target_height: 3_241_368,
            reorg_watch_depth: 24,
            min_pq_quorum_bps: 6_700,
            min_liquidity_settlement_bps: 10_500,
            max_metadata_units: 12,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_receipt_config",
            "chain_id": self.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "release_instruction_height": self.release_instruction_height,
            "broadcast_observation_height": self.broadcast_observation_height,
            "confirmation_target_height": self.confirmation_target_height,
            "reorg_watch_depth": self.reorg_watch_depth,
            "min_pq_quorum_bps": self.min_pq_quorum_bps,
            "min_liquidity_settlement_bps": self.min_liquidity_settlement_bps,
            "max_metadata_units": self.max_metadata_units,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-config",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseReceiptRequirement {
    pub lane: ReleaseReceiptLane,
    pub requirement_id: String,
    pub required_root: String,
    pub required_weight_bps: u64,
    pub receipt_critical: bool,
    pub receipt_kind: String,
    pub description: String,
}

impl ReleaseReceiptRequirement {
    pub fn new(
        config: &Config,
        lane: ReleaseReceiptLane,
        receipt_kind: &str,
        required_weight_bps: u64,
        receipt_critical: bool,
        description: &str,
    ) -> Self {
        let required_root = required_receipt_root(config, &lane, receipt_kind);
        let requirement_id = domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-requirement-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(lane.as_str()),
                HashPart::Str(receipt_kind),
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
            receipt_critical,
            receipt_kind: receipt_kind.to_string(),
            description: description.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_receipt_requirement",
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "requirement_id": self.requirement_id,
            "required_root": self.required_root,
            "required_weight_bps": self.required_weight_bps,
            "receipt_critical": self.receipt_critical,
            "receipt_kind": self.receipt_kind,
            "description": self.description,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-requirement",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseReceiptRecord {
    pub lane: ReleaseReceiptLane,
    pub receipt_id: String,
    pub requirement_id: String,
    pub expected_root: String,
    pub supplied_root: String,
    pub status: ReleaseReceiptStatus,
    pub observation_weight_bps: u64,
    pub confirmation_depth: u64,
    pub hold_count: u64,
    pub redacted_receipt_root: String,
}

impl ReleaseReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_receipt_record",
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "receipt_id": self.receipt_id,
            "requirement_id": self.requirement_id,
            "expected_root": self.expected_root,
            "supplied_root": self.supplied_root,
            "status": self.status.as_str(),
            "observation_weight_bps": self.observation_weight_bps,
            "confirmation_depth": self.confirmation_depth,
            "hold_count": self.hold_count,
            "redacted_receipt_root": self.redacted_receipt_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-record",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseReceiptGap {
    pub lane: ReleaseReceiptLane,
    pub gap_id: String,
    pub requirement_id: String,
    pub gap_code: String,
    pub severity_bps: u64,
    pub expected_root: String,
    pub supplied_root: String,
    pub hold_reason: String,
}

impl ReleaseReceiptGap {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_receipt_gap",
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "gap_id": self.gap_id,
            "requirement_id": self.requirement_id,
            "gap_code": self.gap_code,
            "severity_bps": self.severity_bps,
            "expected_root": self.expected_root,
            "supplied_root": self.supplied_root,
            "hold_reason": self.hold_reason,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-gap",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseReceiptCounters {
    pub requirement_count: u64,
    pub record_count: u64,
    pub accepted_count: u64,
    pub pending_count: u64,
    pub watch_count: u64,
    pub blocked_count: u64,
    pub gap_count: u64,
    pub critical_hold_count: u64,
}

impl ReleaseReceiptCounters {
    pub fn from_records(
        requirements: &[ReleaseReceiptRequirement],
        records: &[ReleaseReceiptRecord],
        gaps: &[ReleaseReceiptGap],
    ) -> Self {
        let accepted_count = records
            .iter()
            .filter(|record| record.status == ReleaseReceiptStatus::Accepted)
            .count() as u64;
        let pending_count = records
            .iter()
            .filter(|record| record.status == ReleaseReceiptStatus::Pending)
            .count() as u64;
        let watch_count = records
            .iter()
            .filter(|record| record.status == ReleaseReceiptStatus::Watch)
            .count() as u64;
        let blocked_count = records
            .iter()
            .filter(|record| record.status == ReleaseReceiptStatus::Blocked)
            .count() as u64;
        let critical_hold_count = requirements
            .iter()
            .filter(|requirement| {
                requirement.receipt_critical
                    && records.iter().any(|record| {
                        record.requirement_id == requirement.requirement_id
                            && record.status.blocks_acceptance()
                    })
            })
            .count() as u64;
        Self {
            requirement_count: requirements.len() as u64,
            record_count: records.len() as u64,
            accepted_count,
            pending_count,
            watch_count,
            blocked_count,
            gap_count: gaps.len() as u64,
            critical_hold_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_receipt_counters",
            "requirement_count": self.requirement_count,
            "record_count": self.record_count,
            "accepted_count": self.accepted_count,
            "pending_count": self.pending_count,
            "watch_count": self.watch_count,
            "blocked_count": self.blocked_count,
            "gap_count": self.gap_count,
            "critical_hold_count": self.critical_hold_count,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-counters",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseReceiptRoots {
    pub config_root: String,
    pub requirement_root: String,
    pub record_root: String,
    pub gap_root: String,
    pub lane_status_root: String,
    pub redacted_receipt_root: String,
    pub release_receipt_root: String,
    pub manifest_id: String,
}

impl ReleaseReceiptRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_receipt_roots",
            "config_root": self.config_root,
            "requirement_root": self.requirement_root,
            "record_root": self.record_root,
            "gap_root": self.gap_root,
            "lane_status_root": self.lane_status_root,
            "redacted_receipt_root": self.redacted_receipt_root,
            "release_receipt_root": self.release_receipt_root,
            "manifest_id": self.manifest_id,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-roots",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseReceiptManifest {
    pub manifest_id: String,
    pub verdict: ReleaseReceiptVerdict,
    pub counters: ReleaseReceiptCounters,
    pub roots: ReleaseReceiptRoots,
    pub release_holds: BTreeMap<String, String>,
}

impl ReleaseReceiptManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_receipt_manifest",
            "manifest_id": self.manifest_id,
            "verdict": self.verdict.as_str(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "release_holds": self.release_holds,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-manifest",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub requirements: Vec<ReleaseReceiptRequirement>,
    pub records: Vec<ReleaseReceiptRecord>,
    pub gaps: Vec<ReleaseReceiptGap>,
    pub manifest: ReleaseReceiptManifest,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let requirements = release_receipt_requirements(&config);
        let records = release_receipt_records(&config, &requirements);
        let gaps = release_receipt_gaps(&requirements, &records);
        let counters = ReleaseReceiptCounters::from_records(&requirements, &records, &gaps);
        let release_holds = release_hold_map(&requirements, &records, &gaps);
        let roots = release_receipt_roots(&config, &requirements, &records, &gaps);
        let verdict = manifest_verdict(&counters);
        let manifest = ReleaseReceiptManifest {
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
            gaps,
            manifest,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_receipt_manifest_state",
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "requirements": self
                .requirements
                .iter()
                .map(ReleaseReceiptRequirement::public_record)
                .collect::<Vec<_>>(),
            "records": self
                .records
                .iter()
                .map(ReleaseReceiptRecord::public_record)
                .collect::<Vec<_>>(),
            "gaps": self
                .gaps
                .iter()
                .map(ReleaseReceiptGap::public_record)
                .collect::<Vec<_>>(),
            "manifest": self.manifest.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-state",
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

fn release_receipt_requirements(config: &Config) -> Vec<ReleaseReceiptRequirement> {
    vec![
        ReleaseReceiptRequirement::new(
            config,
            ReleaseReceiptLane::ReleaseInstruction,
            "release_instruction_root_and_issue_verdict",
            9_500,
            true,
            "Release receipt must bind the accepted custody release instruction and issue-or-hold verdict.",
        ),
        ReleaseReceiptRequirement::new(
            config,
            ReleaseReceiptLane::WalletReceipt,
            "wallet_release_receipt_and_encrypted_notice",
            9_000,
            true,
            "Wallet receipt must bind payout commitment, claim root, encrypted notice, and user-visible receipt fields.",
        ),
        ReleaseReceiptRequirement::new(
            config,
            ReleaseReceiptLane::MoneroBroadcast,
            "monero_broadcast_observation_receipt",
            9_000,
            true,
            "Monero broadcast receipt must bind transaction envelope, fee bounds, mempool observation, and confirmation target.",
        ),
        ReleaseReceiptRequirement::new(
            config,
            ReleaseReceiptLane::PqCustodySignature,
            "pq_custody_signature_receipt",
            config.min_pq_quorum_bps,
            true,
            "PQ custody signature receipt must bind signer quorum, signature domain, key epoch, and watcher attestations.",
        ),
        ReleaseReceiptRequirement::new(
            config,
            ReleaseReceiptLane::LiquiditySettlement,
            "liquidity_release_settlement_receipt",
            config.min_liquidity_settlement_bps,
            true,
            "Liquidity settlement receipt must bind reserve coverage, release amount, backstop use, fee cap, and settlement root.",
        ),
        ReleaseReceiptRequirement::new(
            config,
            ReleaseReceiptLane::ReorgWatch,
            "post_broadcast_reorg_watch_receipt",
            8_500,
            true,
            "Reorg watch receipt must bind confirmation depth and continued observation before release is final.",
        ),
        ReleaseReceiptRequirement::new(
            config,
            ReleaseReceiptLane::PrivacyBoundary,
            "release_receipt_privacy_boundary",
            9_000,
            true,
            "Release receipt must preserve wallet metadata limits and keep private payout fields committed.",
        ),
        ReleaseReceiptRequirement::new(
            config,
            ReleaseReceiptLane::AdversarialReceipt,
            "adversarial_release_receipt_negative_cases",
            9_000,
            true,
            "Adversarial receipt evidence must reject bad signature, broadcast, liquidity, replay, and privacy cases.",
        ),
        ReleaseReceiptRequirement::new(
            config,
            ReleaseReceiptLane::ReleaseBlocker,
            "release_receipt_blocker_clearance",
            10_000,
            true,
            "Release receipt blockers must be cleared or explicitly hold receipt acceptance.",
        ),
    ]
}

fn release_receipt_records(
    config: &Config,
    requirements: &[ReleaseReceiptRequirement],
) -> Vec<ReleaseReceiptRecord> {
    requirements
        .iter()
        .map(|requirement| {
            let supplied_root = supplied_receipt_root(config, requirement);
            let status = status_for(requirement, &supplied_root);
            let hold_count = hold_count_for(requirement, &status, &supplied_root);
            let redacted_receipt_root =
                redacted_receipt_root(config, requirement, &supplied_root, &status);
            let receipt_id = domain_hash(
                "monero-l2-pq-bridge-exit-release-receipt-id",
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
            ReleaseReceiptRecord {
                lane: requirement.lane.clone(),
                receipt_id,
                requirement_id: requirement.requirement_id.clone(),
                expected_root: requirement.required_root.clone(),
                supplied_root,
                status,
                observation_weight_bps: observation_weight_for(requirement),
                confirmation_depth: confirmation_depth_for(config, requirement),
                hold_count,
                redacted_receipt_root,
            }
        })
        .collect()
}

fn required_receipt_root(config: &Config, lane: &ReleaseReceiptLane, receipt_kind: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-release-receipt-required-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(receipt_kind),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::U64(config.release_instruction_height),
            HashPart::U64(config.confirmation_target_height),
        ],
        32,
    )
}

fn supplied_receipt_root(config: &Config, requirement: &ReleaseReceiptRequirement) -> String {
    match requirement.lane {
        ReleaseReceiptLane::ReleaseInstruction
        | ReleaseReceiptLane::WalletReceipt
        | ReleaseReceiptLane::PqCustodySignature
        | ReleaseReceiptLane::PrivacyBoundary => requirement.required_root.clone(),
        ReleaseReceiptLane::MoneroBroadcast => domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-supplied-broadcast",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&requirement.requirement_id),
                HashPart::U64(config.broadcast_observation_height),
            ],
            32,
        ),
        ReleaseReceiptLane::LiquiditySettlement => domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-supplied-liquidity",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&requirement.requirement_id),
                HashPart::U64(config.min_liquidity_settlement_bps - 200),
            ],
            32,
        ),
        ReleaseReceiptLane::ReorgWatch => domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-supplied-reorg-watch",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&requirement.requirement_id),
                HashPart::U64(config.reorg_watch_depth - 6),
            ],
            32,
        ),
        ReleaseReceiptLane::AdversarialReceipt => domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-supplied-adversarial",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&requirement.requirement_id),
                HashPart::Str("negative-case-harness-pending"),
            ],
            32,
        ),
        ReleaseReceiptLane::ReleaseBlocker => domain_hash(
            "monero-l2-pq-bridge-exit-release-receipt-supplied-blocker",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&requirement.requirement_id),
                HashPart::Str("receipt-runtime-and-audit-hold-open"),
            ],
            32,
        ),
    }
}

fn status_for(
    requirement: &ReleaseReceiptRequirement,
    supplied_root: &str,
) -> ReleaseReceiptStatus {
    if supplied_root == requirement.required_root && requirement.required_weight_bps >= 9_000 {
        ReleaseReceiptStatus::Accepted
    } else if supplied_root == requirement.required_root {
        ReleaseReceiptStatus::Pending
    } else {
        match requirement.lane {
            ReleaseReceiptLane::MoneroBroadcast
            | ReleaseReceiptLane::AdversarialReceipt
            | ReleaseReceiptLane::ReleaseBlocker => ReleaseReceiptStatus::Blocked,
            ReleaseReceiptLane::LiquiditySettlement | ReleaseReceiptLane::ReorgWatch => {
                ReleaseReceiptStatus::Watch
            }
            _ => ReleaseReceiptStatus::Pending,
        }
    }
}

fn observation_weight_for(requirement: &ReleaseReceiptRequirement) -> u64 {
    match requirement.lane {
        ReleaseReceiptLane::ReleaseInstruction => 9_700,
        ReleaseReceiptLane::WalletReceipt => 9_300,
        ReleaseReceiptLane::MoneroBroadcast => 8_200,
        ReleaseReceiptLane::PqCustodySignature => 7_400,
        ReleaseReceiptLane::LiquiditySettlement => 10_100,
        ReleaseReceiptLane::ReorgWatch => 8_200,
        ReleaseReceiptLane::PrivacyBoundary => 9_200,
        ReleaseReceiptLane::AdversarialReceipt => 7_900,
        ReleaseReceiptLane::ReleaseBlocker => 6_500,
    }
}

fn confirmation_depth_for(config: &Config, requirement: &ReleaseReceiptRequirement) -> u64 {
    match requirement.lane {
        ReleaseReceiptLane::MoneroBroadcast
        | ReleaseReceiptLane::ReorgWatch
        | ReleaseReceiptLane::WalletReceipt => config.reorg_watch_depth,
        _ => config.reorg_watch_depth / 2,
    }
}

fn hold_count_for(
    requirement: &ReleaseReceiptRequirement,
    status: &ReleaseReceiptStatus,
    supplied_root: &str,
) -> u64 {
    let root_hold = if supplied_root == requirement.required_root {
        0
    } else {
        1
    };
    let status_hold = match status {
        ReleaseReceiptStatus::Accepted => 0,
        ReleaseReceiptStatus::Pending => {
            if requirement.receipt_critical {
                1
            } else {
                0
            }
        }
        ReleaseReceiptStatus::Watch => 1,
        ReleaseReceiptStatus::Blocked => 2,
    };
    root_hold + status_hold
}

fn redacted_receipt_root(
    config: &Config,
    requirement: &ReleaseReceiptRequirement,
    supplied_root: &str,
    status: &ReleaseReceiptStatus,
) -> String {
    let payload = json!({
        "lane": requirement.lane.as_str(),
        "requirement_id": requirement.requirement_id,
        "supplied_root": supplied_root,
        "status": status.as_str(),
        "l2_reference_height": config.l2_reference_height,
        "monero_reference_height": config.monero_reference_height,
        "confirmation_target_height": config.confirmation_target_height,
        "public_fields_only": ["lane", "status", "roots", "heights"],
    });
    domain_hash(
        "monero-l2-pq-bridge-exit-release-receipt-redacted-payload",
        &[HashPart::Json(&payload)],
        32,
    )
}

fn release_receipt_gaps(
    requirements: &[ReleaseReceiptRequirement],
    records: &[ReleaseReceiptRecord],
) -> Vec<ReleaseReceiptGap> {
    requirements
        .iter()
        .filter_map(|requirement| {
            records
                .iter()
                .find(|record| record.requirement_id == requirement.requirement_id)
                .filter(|record| record.status.blocks_acceptance() || record.hold_count > 0)
                .map(|record| {
                    let gap_code = gap_code_for(requirement, record);
                    let hold_reason = hold_reason_for(requirement, record);
                    let gap_id = domain_hash(
                        "monero-l2-pq-bridge-exit-release-receipt-gap-id",
                        &[
                            HashPart::Str(CHAIN_ID),
                            HashPart::Str(PROTOCOL_VERSION),
                            HashPart::Str(requirement.lane.as_str()),
                            HashPart::Str(&requirement.requirement_id),
                            HashPart::Str(&record.supplied_root),
                            HashPart::Str(&gap_code),
                        ],
                        16,
                    );
                    ReleaseReceiptGap {
                        lane: requirement.lane.clone(),
                        gap_id,
                        requirement_id: requirement.requirement_id.clone(),
                        gap_code,
                        severity_bps: gap_severity(requirement, record),
                        expected_root: record.expected_root.clone(),
                        supplied_root: record.supplied_root.clone(),
                        hold_reason,
                    }
                })
        })
        .collect()
}

fn gap_code_for(requirement: &ReleaseReceiptRequirement, record: &ReleaseReceiptRecord) -> String {
    if record.expected_root != record.supplied_root {
        format!("{}_receipt_root_mismatch", requirement.lane.as_str())
    } else if record.status.blocks_acceptance() {
        format!("{}_receipt_status_hold", requirement.lane.as_str())
    } else {
        format!("{}_receipt_pending", requirement.lane.as_str())
    }
}

fn hold_reason_for(
    requirement: &ReleaseReceiptRequirement,
    record: &ReleaseReceiptRecord,
) -> String {
    match requirement.lane {
        ReleaseReceiptLane::ReleaseInstruction => {
            "release receipt must bind the accepted custody release instruction root".to_string()
        }
        ReleaseReceiptLane::WalletReceipt => {
            "wallet release receipt must bind payout commitment, encrypted notice, and claim receipt"
                .to_string()
        }
        ReleaseReceiptLane::MoneroBroadcast => {
            "Monero broadcast receipt must bind transaction envelope, fee bounds, and observation roots"
                .to_string()
        }
        ReleaseReceiptLane::PqCustodySignature => {
            "PQ custody signature receipt must bind quorum, signature domain, key epoch, and watcher attestations"
                .to_string()
        }
        ReleaseReceiptLane::LiquiditySettlement => {
            "liquidity settlement receipt must clear coverage, backstop, fee, and shortfall holds"
                .to_string()
        }
        ReleaseReceiptLane::ReorgWatch => {
            "reorg watch receipt must keep release under observation until confirmation depth is reached"
                .to_string()
        }
        ReleaseReceiptLane::PrivacyBoundary => {
            "release receipt payload must remain within wallet metadata disclosure bounds".to_string()
        }
        ReleaseReceiptLane::AdversarialReceipt => {
            "adversarial release receipt cases must reject bad roots, replay, collusion, and privacy gaps"
                .to_string()
        }
        ReleaseReceiptLane::ReleaseBlocker => format!(
            "release receipt blocker remains {} and holds acceptance",
            record.status.as_str()
        ),
    }
}

fn gap_severity(requirement: &ReleaseReceiptRequirement, record: &ReleaseReceiptRecord) -> u64 {
    let root_penalty = if record.expected_root == record.supplied_root {
        0
    } else {
        3_000
    };
    let status_penalty = match record.status {
        ReleaseReceiptStatus::Accepted => 0,
        ReleaseReceiptStatus::Pending => 1_000,
        ReleaseReceiptStatus::Watch => 1_500,
        ReleaseReceiptStatus::Blocked => 4_000,
    };
    let critical_penalty = if requirement.receipt_critical {
        1_000
    } else {
        0
    };
    (root_penalty + status_penalty + critical_penalty).min(10_000)
}

fn release_receipt_roots(
    config: &Config,
    requirements: &[ReleaseReceiptRequirement],
    records: &[ReleaseReceiptRecord],
    gaps: &[ReleaseReceiptGap],
) -> ReleaseReceiptRoots {
    let config_root = config.state_root();
    let requirement_root = requirement_root(requirements);
    let record_root = record_root(records);
    let gap_root = gap_root(gaps);
    let lane_status_root = lane_status_root(records);
    let redacted_receipt_root = redacted_receipt_set_root(records);
    let release_receipt_root = domain_hash(
        "monero-l2-pq-bridge-exit-release-receipt-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config_root),
            HashPart::Str(&requirement_root),
            HashPart::Str(&record_root),
            HashPart::Str(&gap_root),
            HashPart::Str(&lane_status_root),
            HashPart::Str(&redacted_receipt_root),
        ],
        32,
    );
    let manifest_id = domain_hash(
        "monero-l2-pq-bridge-exit-release-receipt-manifest-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::U64(config.confirmation_target_height),
            HashPart::Str(&release_receipt_root),
            HashPart::Str(&gap_root),
        ],
        16,
    );
    ReleaseReceiptRoots {
        config_root,
        requirement_root,
        record_root,
        gap_root,
        lane_status_root,
        redacted_receipt_root,
        release_receipt_root,
        manifest_id,
    }
}

fn requirement_root(requirements: &[ReleaseReceiptRequirement]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-release-receipt-requirements",
        &requirements
            .iter()
            .map(ReleaseReceiptRequirement::public_record)
            .collect::<Vec<_>>(),
    )
}

fn record_root(records: &[ReleaseReceiptRecord]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-release-receipt-records",
        &records
            .iter()
            .map(ReleaseReceiptRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

fn gap_root(gaps: &[ReleaseReceiptGap]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-release-receipt-gaps",
        &gaps
            .iter()
            .map(ReleaseReceiptGap::public_record)
            .collect::<Vec<_>>(),
    )
}

fn lane_status_root(records: &[ReleaseReceiptRecord]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            json!({
                "lane": record.lane.as_str(),
                "status": record.status.as_str(),
                "hold_count": record.hold_count,
                "confirmation_depth": record.confirmation_depth,
                "receipt_root": record.state_root(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-release-receipt-lane-status",
        &leaves,
    )
}

fn redacted_receipt_set_root(records: &[ReleaseReceiptRecord]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-release-receipt-redacted-set",
        &records
            .iter()
            .map(|record| {
                json!({
                    "lane": record.lane.as_str(),
                    "status": record.status.as_str(),
                    "redacted_receipt_root": record.redacted_receipt_root,
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn release_hold_map(
    requirements: &[ReleaseReceiptRequirement],
    records: &[ReleaseReceiptRecord],
    gaps: &[ReleaseReceiptGap],
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(
        "runtime_execution".to_string(),
        "release receipts still require cargo/runtime execution before production acceptance"
            .to_string(),
    );
    map.insert(
        "live_monero_observation".to_string(),
        "live Monero broadcast and reorg watch receipts remain deferred".to_string(),
    );
    for gap in gaps {
        map.insert(
            format!("gap_{}", gap.lane.as_str()),
            gap.hold_reason.clone(),
        );
    }
    for requirement in requirements {
        if let Some(record) = records
            .iter()
            .find(|item| item.requirement_id == requirement.requirement_id)
        {
            if record.status.blocks_acceptance() {
                map.insert(
                    format!("lane_{}", requirement.lane.as_str()),
                    hold_reason_for(requirement, record),
                );
            }
        }
    }
    map
}

fn manifest_verdict(counters: &ReleaseReceiptCounters) -> ReleaseReceiptVerdict {
    if counters.critical_hold_count == 0 && counters.blocked_count == 0 && counters.gap_count == 0 {
        ReleaseReceiptVerdict::AcceptReceipt
    } else if counters.blocked_count == 0 {
        ReleaseReceiptVerdict::HoldReceipt
    } else {
        ReleaseReceiptVerdict::RejectReceipt
    }
}
