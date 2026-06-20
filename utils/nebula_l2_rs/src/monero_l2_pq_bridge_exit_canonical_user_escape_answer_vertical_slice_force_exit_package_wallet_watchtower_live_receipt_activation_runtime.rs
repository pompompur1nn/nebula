use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageWalletWatchtowerLiveReceiptActivationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_WALLET_WATCHTOWER_LIVE_RECEIPT_ACTIVATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-wallet-watchtower-live-receipt-activation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_WALLET_WATCHTOWER_LIVE_RECEIPT_ACTIVATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ACTIVATION_SUITE: &str =
    "monero-l2-pq-force-exit-package-wallet-watchtower-live-receipt-activation-v1";
pub const DEFAULT_ACTIVATION_EPOCH: u64 = 78;
pub const DEFAULT_WALLET_SCAN_HEIGHT: u64 = 2_772_640;
pub const DEFAULT_WATCHTOWER_REPLAY_HEIGHT: u64 = 2_772_646;
pub const DEFAULT_RELEASE_POLICY_HEIGHT: u64 = 2_772_650;
pub const DEFAULT_FRESHNESS_WINDOW: u64 = 16;
pub const DEFAULT_MIN_WALLET_TRANSCRIPTS: u64 = 5;
pub const DEFAULT_MIN_WATCHTOWER_QUORUM: u64 = 4;
pub const DEFAULT_MIN_RECOVERY_EVIDENCE: u64 = 3;
pub const DEFAULT_MIN_LIVE_RECEIPTS: u64 = 6;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub activation_suite: String,
    pub activation_epoch: u64,
    pub wallet_scan_height: u64,
    pub watchtower_replay_height: u64,
    pub release_policy_height: u64,
    pub freshness_window: u64,
    pub min_wallet_transcripts: u64,
    pub min_watchtower_quorum: u64,
    pub min_recovery_evidence: u64,
    pub min_live_receipts: u64,
    pub require_wallet_scan_recovery: bool,
    pub require_watchtower_replay_receipts: bool,
    pub require_release_policy_binding: bool,
    pub require_zero_mismatches: bool,
    pub hold_on_freshness_gap: bool,
    pub force_exit_release_fail_closed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            activation_suite: ACTIVATION_SUITE.to_string(),
            activation_epoch: DEFAULT_ACTIVATION_EPOCH,
            wallet_scan_height: DEFAULT_WALLET_SCAN_HEIGHT,
            watchtower_replay_height: DEFAULT_WATCHTOWER_REPLAY_HEIGHT,
            release_policy_height: DEFAULT_RELEASE_POLICY_HEIGHT,
            freshness_window: DEFAULT_FRESHNESS_WINDOW,
            min_wallet_transcripts: DEFAULT_MIN_WALLET_TRANSCRIPTS,
            min_watchtower_quorum: DEFAULT_MIN_WATCHTOWER_QUORUM,
            min_recovery_evidence: DEFAULT_MIN_RECOVERY_EVIDENCE,
            min_live_receipts: DEFAULT_MIN_LIVE_RECEIPTS,
            require_wallet_scan_recovery: true,
            require_watchtower_replay_receipts: true,
            require_release_policy_binding: true,
            require_zero_mismatches: true,
            hold_on_freshness_gap: true,
            force_exit_release_fail_closed: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "activation_suite": self.activation_suite,
            "activation_epoch": self.activation_epoch,
            "wallet_scan_height": self.wallet_scan_height,
            "watchtower_replay_height": self.watchtower_replay_height,
            "release_policy_height": self.release_policy_height,
            "freshness_window": self.freshness_window,
            "min_wallet_transcripts": self.min_wallet_transcripts,
            "min_watchtower_quorum": self.min_watchtower_quorum,
            "min_recovery_evidence": self.min_recovery_evidence,
            "min_live_receipts": self.min_live_receipts,
            "require_wallet_scan_recovery": self.require_wallet_scan_recovery,
            "require_watchtower_replay_receipts": self.require_watchtower_replay_receipts,
            "require_release_policy_binding": self.require_release_policy_binding,
            "require_zero_mismatches": self.require_zero_mismatches,
            "hold_on_freshness_gap": self.hold_on_freshness_gap,
            "force_exit_release_fail_closed": self.force_exit_release_fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptLaneKind {
    WalletScanTranscript,
    WalletRecoveryTranscript,
    WatchtowerReplayReceipt,
    WatchtowerQuorumAttestation,
    ReleasePolicyBinding,
    FreshnessHold,
    MismatchHold,
}

impl ReceiptLaneKind {
    pub fn ordered() -> &'static [Self] {
        &[
            Self::WalletScanTranscript,
            Self::WalletRecoveryTranscript,
            Self::WatchtowerReplayReceipt,
            Self::WatchtowerQuorumAttestation,
            Self::ReleasePolicyBinding,
            Self::FreshnessHold,
            Self::MismatchHold,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScanTranscript => "wallet_scan_transcript",
            Self::WalletRecoveryTranscript => "wallet_recovery_transcript",
            Self::WatchtowerReplayReceipt => "watchtower_replay_receipt",
            Self::WatchtowerQuorumAttestation => "watchtower_quorum_attestation",
            Self::ReleasePolicyBinding => "release_policy_binding",
            Self::FreshnessHold => "freshness_hold",
            Self::MismatchHold => "mismatch_hold",
        }
    }

    pub fn is_hold(self) -> bool {
        matches!(self, Self::FreshnessHold | Self::MismatchHold)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Accepted,
    Pending,
    Mismatch,
    Stale,
    Held,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Pending => "pending",
            Self::Mismatch => "mismatch",
            Self::Stale => "stale",
            Self::Held => "held",
        }
    }

    pub fn counts_as_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }

    pub fn counts_as_mismatch(self) -> bool {
        matches!(self, Self::Mismatch)
    }

    pub fn counts_as_freshness_hold(self) -> bool {
        matches!(self, Self::Stale | Self::Held)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptLane {
    pub lane_id: String,
    pub ordinal: u64,
    pub kind: ReceiptLaneKind,
    pub status: EvidenceStatus,
    pub observed_height: u64,
    pub reference_root: String,
    pub observed_root: String,
    pub transcript_root: String,
    pub quorum_root: String,
    pub recovery_evidence_root: String,
    pub live_receipt_root: String,
    pub policy_binding_root: String,
}

impl ReceiptLane {
    pub fn new(
        config: &Config,
        ordinal: u64,
        kind: ReceiptLaneKind,
        status: EvidenceStatus,
        observed_height: u64,
    ) -> Self {
        let lane_id = deterministic_id("receipt-lane", kind.as_str(), ordinal);
        let reference_root = lane_reference_root(config, kind, ordinal);
        let observed_root = if status.counts_as_mismatch() {
            domain_hash(
                "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-ACTIVATION-MISMATCHED-OBSERVED",
                &[
                    HashPart::Str(kind.as_str()),
                    HashPart::U64(ordinal),
                    HashPart::U64(observed_height),
                ],
                32,
            )
        } else {
            reference_root.clone()
        };
        let transcript_root = component_root("wallet-transcript", kind, ordinal, &observed_root);
        let quorum_root = component_root("watchtower-quorum", kind, ordinal, &observed_root);
        let recovery_evidence_root =
            component_root("recovery-evidence", kind, ordinal, &observed_root);
        let live_receipt_root = component_root("live-receipt", kind, ordinal, &observed_root);
        let policy_binding_root = component_root("policy-binding", kind, ordinal, &observed_root);
        Self {
            lane_id,
            ordinal,
            kind,
            status,
            observed_height,
            reference_root,
            observed_root,
            transcript_root,
            quorum_root,
            recovery_evidence_root,
            live_receipt_root,
            policy_binding_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "ordinal": self.ordinal,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "observed_height": self.observed_height,
            "reference_root": self.reference_root,
            "observed_root": self.observed_root,
            "transcript_root": self.transcript_root,
            "quorum_root": self.quorum_root,
            "recovery_evidence_root": self.recovery_evidence_root,
            "live_receipt_root": self.live_receipt_root,
            "policy_binding_root": self.policy_binding_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt-lane", &self.public_record())
    }

    pub fn is_fresh_for(&self, config: &Config) -> bool {
        self.observed_height <= config.release_policy_height
            && config
                .release_policy_height
                .saturating_sub(self.observed_height)
                <= config.freshness_window
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub wallet_scan_transcript_root: String,
    pub wallet_recovery_transcript_root: String,
    pub wallet_transcript_root: String,
    pub watchtower_replay_receipt_root: String,
    pub watchtower_quorum_attestation_root: String,
    pub watchtower_quorum_root: String,
    pub recovery_evidence_root: String,
    pub live_receipt_root: String,
    pub release_policy_binding_root: String,
    pub mismatch_hold_root: String,
    pub freshness_hold_root: String,
    pub lane_commitment_root: String,
    pub activation_verdict_root: String,
    pub state_commitment_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "wallet_scan_transcript_root": self.wallet_scan_transcript_root,
            "wallet_recovery_transcript_root": self.wallet_recovery_transcript_root,
            "wallet_transcript_root": self.wallet_transcript_root,
            "watchtower_replay_receipt_root": self.watchtower_replay_receipt_root,
            "watchtower_quorum_attestation_root": self.watchtower_quorum_attestation_root,
            "watchtower_quorum_root": self.watchtower_quorum_root,
            "recovery_evidence_root": self.recovery_evidence_root,
            "live_receipt_root": self.live_receipt_root,
            "release_policy_binding_root": self.release_policy_binding_root,
            "mismatch_hold_root": self.mismatch_hold_root,
            "freshness_hold_root": self.freshness_hold_root,
            "lane_commitment_root": self.lane_commitment_root,
            "activation_verdict_root": self.activation_verdict_root,
            "state_commitment_root": self.state_commitment_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lane_count: u64,
    pub accepted_lane_count: u64,
    pub pending_lane_count: u64,
    pub mismatch_count: u64,
    pub freshness_hold_count: u64,
    pub wallet_transcript_count: u64,
    pub wallet_recovery_count: u64,
    pub watchtower_replay_count: u64,
    pub watchtower_quorum_count: u64,
    pub recovery_evidence_count: u64,
    pub live_receipt_count: u64,
    pub release_policy_binding_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "accepted_lane_count": self.accepted_lane_count,
            "pending_lane_count": self.pending_lane_count,
            "mismatch_count": self.mismatch_count,
            "freshness_hold_count": self.freshness_hold_count,
            "wallet_transcript_count": self.wallet_transcript_count,
            "wallet_recovery_count": self.wallet_recovery_count,
            "watchtower_replay_count": self.watchtower_replay_count,
            "watchtower_quorum_count": self.watchtower_quorum_count,
            "recovery_evidence_count": self.recovery_evidence_count,
            "live_receipt_count": self.live_receipt_count,
            "release_policy_binding_count": self.release_policy_binding_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStatus {
    Activated,
    HeldForMismatch,
    HeldForFreshness,
    HeldForQuorum,
    HeldForRecovery,
    HeldForPolicy,
}

impl ActivationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Activated => "activated",
            Self::HeldForMismatch => "held_for_mismatch",
            Self::HeldForFreshness => "held_for_freshness",
            Self::HeldForQuorum => "held_for_quorum",
            Self::HeldForRecovery => "held_for_recovery",
            Self::HeldForPolicy => "held_for_policy",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleasePolicyDecision {
    ReleaseForceExit,
    HoldForceExit,
}

impl ReleasePolicyDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseForceExit => "release_force_exit",
            Self::HoldForceExit => "hold_force_exit",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivationVerdict {
    pub status: ActivationStatus,
    pub decision: ReleasePolicyDecision,
    pub wallet_ready: bool,
    pub watchtower_ready: bool,
    pub recovery_ready: bool,
    pub live_receipts_ready: bool,
    pub policy_binding_ready: bool,
    pub mismatches_clear: bool,
    pub freshness_clear: bool,
    pub force_exit_release_allowed: bool,
    pub activation_id: String,
    pub user_escape_answer: String,
    pub production_answer: String,
    pub verdict_root: String,
}

impl ActivationVerdict {
    pub fn new(config: &Config, roots: &Roots, counters: &Counters) -> Self {
        let wallet_ready = counters.wallet_transcript_count >= config.min_wallet_transcripts;
        let watchtower_ready = counters.watchtower_quorum_count >= config.min_watchtower_quorum
            && counters.watchtower_replay_count >= config.min_watchtower_quorum;
        let recovery_ready = counters.recovery_evidence_count >= config.min_recovery_evidence
            && counters.wallet_recovery_count >= config.min_recovery_evidence;
        let live_receipts_ready = counters.live_receipt_count >= config.min_live_receipts;
        let policy_binding_ready = counters.release_policy_binding_count > 0;
        let mismatches_clear = counters.mismatch_count == 0;
        let freshness_clear = counters.freshness_hold_count == 0;
        let required_ready =
            optional_requirement(config.require_wallet_scan_recovery, wallet_ready)
                && optional_requirement(
                    config.require_watchtower_replay_receipts,
                    watchtower_ready,
                )
                && optional_requirement(
                    config.require_release_policy_binding,
                    policy_binding_ready,
                )
                && recovery_ready
                && live_receipts_ready;
        let release_clear = required_ready
            && optional_requirement(config.require_zero_mismatches, mismatches_clear)
            && optional_requirement(config.hold_on_freshness_gap, freshness_clear);
        let status = if config.require_zero_mismatches && !mismatches_clear {
            ActivationStatus::HeldForMismatch
        } else if config.hold_on_freshness_gap && !freshness_clear {
            ActivationStatus::HeldForFreshness
        } else if !watchtower_ready {
            ActivationStatus::HeldForQuorum
        } else if !recovery_ready {
            ActivationStatus::HeldForRecovery
        } else if !policy_binding_ready {
            ActivationStatus::HeldForPolicy
        } else {
            ActivationStatus::Activated
        };
        let force_exit_release_allowed = release_clear
            && (!config.force_exit_release_fail_closed || status == ActivationStatus::Activated);
        let decision = if force_exit_release_allowed {
            ReleasePolicyDecision::ReleaseForceExit
        } else {
            ReleasePolicyDecision::HoldForceExit
        };
        let activation_id = deterministic_id(
            "wallet-watchtower-live-receipt-activation",
            &config.activation_suite,
            config.activation_epoch,
        );
        let verdict_root = activation_verdict_root(
            config,
            roots,
            counters,
            status,
            decision,
            wallet_ready,
            watchtower_ready,
            recovery_ready,
            live_receipts_ready,
            policy_binding_ready,
            mismatches_clear,
            freshness_clear,
        );
        let user_escape_answer = if force_exit_release_allowed {
            "wallet scan recovery and watchtower replay receipts activate force-exit release"
                .to_string()
        } else {
            "force-exit release remains held until wallet/watchtower receipt activation clears"
                .to_string()
        };
        let production_answer = if force_exit_release_allowed {
            "activate wallet-watchtower live receipt release policy".to_string()
        } else {
            "hold wallet-watchtower live receipt release policy".to_string()
        };
        Self {
            status,
            decision,
            wallet_ready,
            watchtower_ready,
            recovery_ready,
            live_receipts_ready,
            policy_binding_ready,
            mismatches_clear,
            freshness_clear,
            force_exit_release_allowed,
            activation_id,
            user_escape_answer,
            production_answer,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "decision": self.decision.as_str(),
            "wallet_ready": self.wallet_ready,
            "watchtower_ready": self.watchtower_ready,
            "recovery_ready": self.recovery_ready,
            "live_receipts_ready": self.live_receipts_ready,
            "policy_binding_ready": self.policy_binding_ready,
            "mismatches_clear": self.mismatches_clear,
            "freshness_clear": self.freshness_clear,
            "force_exit_release_allowed": self.force_exit_release_allowed,
            "activation_id": self.activation_id,
            "user_escape_answer": self.user_escape_answer,
            "production_answer": self.production_answer,
            "verdict_root": self.verdict_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("activation-verdict", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub lanes: Vec<ReceiptLane>,
    pub roots: Roots,
    pub counters: Counters,
    pub verdict: ActivationVerdict,
}

impl State {
    pub fn new(config: Config, lanes: Vec<ReceiptLane>) -> Result<Self> {
        validate_config(&config)?;
        ensure(
            !lanes.is_empty(),
            "wallet watchtower activation has no lanes",
        )?;
        Ok(state_from_parts(config, lanes))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "lanes": self.lanes.iter().map(ReceiptLane::public_record).collect::<Vec<_>>(),
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "verdict": self.verdict.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_commitment_root.clone()
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let mut lanes = Vec::new();
    let mut ordinal = 0_u64;
    for kind in ReceiptLaneKind::ordered() {
        let count = default_lane_count(*kind);
        for offset in 0..count {
            let observed_height = observed_height_for(&config, *kind, offset);
            lanes.push(ReceiptLane::new(
                &config,
                ordinal,
                *kind,
                EvidenceStatus::Accepted,
                observed_height,
            ));
            ordinal = ordinal.saturating_add(1);
        }
    }
    state_from_parts(config, lanes)
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-LIVE-RECEIPT-ACTIVATION-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn deterministic_id(namespace: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-LIVE-RECEIPT-ACTIVATION-ID",
        &[
            HashPart::Str(namespace),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        16,
    )
}

fn lane_reference_root(config: &Config, kind: ReceiptLaneKind, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-LIVE-RECEIPT-ACTIVATION-REFERENCE",
        &[
            HashPart::Str(&config.activation_suite),
            HashPart::Str(kind.as_str()),
            HashPart::U64(config.activation_epoch),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn component_root(
    kind: &str,
    lane_kind: ReceiptLaneKind,
    ordinal: u64,
    observed_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-LIVE-RECEIPT-ACTIVATION-COMPONENT",
        &[
            HashPart::Str(kind),
            HashPart::Str(lane_kind.as_str()),
            HashPart::U64(ordinal),
            HashPart::Str(observed_root),
        ],
        32,
    )
}

fn lane_kind_root(lanes: &[ReceiptLane], kind: ReceiptLaneKind) -> String {
    let leaves = lanes
        .iter()
        .filter(|lane| lane.kind == kind)
        .map(ReceiptLane::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-LIVE-RECEIPT-ACTIVATION-LANE-KIND",
        &leaves,
    )
}

fn component_collection_root<F>(kind: &str, lanes: &[ReceiptLane], select: F) -> String
where
    F: Fn(&ReceiptLane) -> &String,
{
    let leaves = lanes
        .iter()
        .map(|lane| {
            json!({
                "kind": kind,
                "lane_id": lane.lane_id,
                "ordinal": lane.ordinal,
                "component_root": select(lane),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-LIVE-RECEIPT-ACTIVATION-COMPONENT-COLLECTION",
        &leaves,
    )
}

fn combined_root(kind: &str, roots: &[String]) -> String {
    let leaves = roots
        .iter()
        .enumerate()
        .map(|(ordinal, root)| {
            json!({
                "kind": kind,
                "ordinal": ordinal as u64,
                "root": root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-LIVE-RECEIPT-ACTIVATION-COMBINED",
        &leaves,
    )
}

fn status_root(lanes: &[ReceiptLane], status: EvidenceStatus) -> String {
    let leaves = lanes
        .iter()
        .filter(|lane| lane.status == status)
        .map(ReceiptLane::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-LIVE-RECEIPT-ACTIVATION-STATUS",
        &leaves,
    )
}

fn freshness_hold_root(config: &Config, lanes: &[ReceiptLane]) -> String {
    let leaves = lanes
        .iter()
        .filter(|lane| !lane.is_fresh_for(config) || lane.status.counts_as_freshness_hold())
        .map(ReceiptLane::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-LIVE-RECEIPT-ACTIVATION-FRESHNESS-HOLD",
        &leaves,
    )
}

fn lane_commitment_root(lanes: &[ReceiptLane]) -> String {
    let leaves = lanes
        .iter()
        .map(|lane| {
            json!({
                "lane_id": lane.lane_id,
                "state_root": lane.state_root(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-LIVE-RECEIPT-ACTIVATION-LANES",
        &leaves,
    )
}

fn counters(config: &Config, lanes: &[ReceiptLane]) -> Counters {
    let accepted_lane_count = count_where(lanes, |lane| lane.status.counts_as_accepted());
    let pending_lane_count = count_where(lanes, |lane| lane.status == EvidenceStatus::Pending);
    let mismatch_count = count_where(lanes, |lane| lane.status.counts_as_mismatch());
    let freshness_hold_count = count_where(lanes, |lane| {
        lane.status.counts_as_freshness_hold() || !lane.is_fresh_for(config)
    });
    let wallet_transcript_count = count_where(lanes, |lane| {
        lane.status.counts_as_accepted()
            && matches!(
                lane.kind,
                ReceiptLaneKind::WalletScanTranscript | ReceiptLaneKind::WalletRecoveryTranscript
            )
    });
    let wallet_recovery_count = count_kind(lanes, ReceiptLaneKind::WalletRecoveryTranscript);
    let watchtower_replay_count = count_kind(lanes, ReceiptLaneKind::WatchtowerReplayReceipt);
    let watchtower_quorum_count = count_kind(lanes, ReceiptLaneKind::WatchtowerQuorumAttestation);
    let recovery_evidence_count = count_where(lanes, |lane| {
        lane.status.counts_as_accepted()
            && matches!(
                lane.kind,
                ReceiptLaneKind::WalletRecoveryTranscript
                    | ReceiptLaneKind::WatchtowerQuorumAttestation
            )
    });
    let live_receipt_count = count_where(lanes, |lane| {
        lane.status.counts_as_accepted()
            && matches!(
                lane.kind,
                ReceiptLaneKind::WatchtowerReplayReceipt
                    | ReceiptLaneKind::WatchtowerQuorumAttestation
                    | ReceiptLaneKind::ReleasePolicyBinding
            )
    });
    let release_policy_binding_count = count_kind(lanes, ReceiptLaneKind::ReleasePolicyBinding);
    Counters {
        lane_count: lanes.len() as u64,
        accepted_lane_count,
        pending_lane_count,
        mismatch_count,
        freshness_hold_count,
        wallet_transcript_count,
        wallet_recovery_count,
        watchtower_replay_count,
        watchtower_quorum_count,
        recovery_evidence_count,
        live_receipt_count,
        release_policy_binding_count,
    }
}

fn count_kind(lanes: &[ReceiptLane], kind: ReceiptLaneKind) -> u64 {
    count_where(lanes, |lane| {
        lane.kind == kind && lane.status.counts_as_accepted()
    })
}

fn count_where<F>(lanes: &[ReceiptLane], predicate: F) -> u64
where
    F: Fn(&ReceiptLane) -> bool,
{
    lanes.iter().filter(|lane| predicate(lane)).count() as u64
}

fn activation_verdict_root(
    config: &Config,
    roots: &Roots,
    counters: &Counters,
    status: ActivationStatus,
    decision: ReleasePolicyDecision,
    wallet_ready: bool,
    watchtower_ready: bool,
    recovery_ready: bool,
    live_receipts_ready: bool,
    policy_binding_ready: bool,
    mismatches_clear: bool,
    freshness_clear: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-LIVE-RECEIPT-ACTIVATION-VERDICT",
        &[
            HashPart::Str(&config.activation_suite),
            HashPart::Str(&roots.wallet_transcript_root),
            HashPart::Str(&roots.watchtower_quorum_root),
            HashPart::Str(&roots.recovery_evidence_root),
            HashPart::Str(&roots.live_receipt_root),
            HashPart::Str(&roots.release_policy_binding_root),
            HashPart::Str(&roots.mismatch_hold_root),
            HashPart::Str(&roots.freshness_hold_root),
            HashPart::U64(counters.wallet_transcript_count),
            HashPart::U64(counters.watchtower_quorum_count),
            HashPart::U64(counters.recovery_evidence_count),
            HashPart::U64(counters.live_receipt_count),
            HashPart::U64(counters.mismatch_count),
            HashPart::U64(counters.freshness_hold_count),
            HashPart::Str(status.as_str()),
            HashPart::Str(decision.as_str()),
            HashPart::Str(bool_str(wallet_ready)),
            HashPart::Str(bool_str(watchtower_ready)),
            HashPart::Str(bool_str(recovery_ready)),
            HashPart::Str(bool_str(live_receipts_ready)),
            HashPart::Str(bool_str(policy_binding_ready)),
            HashPart::Str(bool_str(mismatches_clear)),
            HashPart::Str(bool_str(freshness_clear)),
        ],
        32,
    )
}

fn state_commitment_root(
    config: &Config,
    roots: &Roots,
    counters: &Counters,
    verdict: &ActivationVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-FORCE-EXIT-WALLET-WATCHTOWER-LIVE-RECEIPT-ACTIVATION-STATE",
        &[
            HashPart::Str(&config.state_root()),
            HashPart::Str(&roots.wallet_transcript_root),
            HashPart::Str(&roots.watchtower_quorum_root),
            HashPart::Str(&roots.recovery_evidence_root),
            HashPart::Str(&roots.live_receipt_root),
            HashPart::Str(&roots.release_policy_binding_root),
            HashPart::Str(&roots.mismatch_hold_root),
            HashPart::Str(&roots.freshness_hold_root),
            HashPart::Str(&roots.lane_commitment_root),
            HashPart::Str(&roots.activation_verdict_root),
            HashPart::Str(&counters.state_root()),
            HashPart::Str(&verdict.verdict_root),
        ],
        32,
    )
}

fn validate_config(config: &Config) -> Result<()> {
    ensure(
        config.chain_id == CHAIN_ID,
        "wallet watchtower activation chain id mismatch",
    )?;
    ensure(
        config.protocol_version == PROTOCOL_VERSION,
        "wallet watchtower activation protocol mismatch",
    )?;
    ensure(
        config.schema_version == SCHEMA_VERSION,
        "wallet watchtower activation schema mismatch",
    )?;
    ensure(
        config.min_wallet_transcripts > 0,
        "wallet watchtower activation requires wallet transcripts",
    )?;
    ensure(
        config.min_watchtower_quorum > 0,
        "wallet watchtower activation requires watchtower quorum",
    )?;
    ensure(
        config.min_recovery_evidence > 0,
        "wallet watchtower activation requires recovery evidence",
    )?;
    ensure(
        config.min_live_receipts > 0,
        "wallet watchtower activation requires live receipts",
    )?;
    ensure(
        config.release_policy_height >= config.wallet_scan_height,
        "wallet watchtower activation release policy predates wallet scan",
    )?;
    ensure(
        config.release_policy_height >= config.watchtower_replay_height,
        "wallet watchtower activation release policy predates watchtower replay",
    )?;
    Ok(())
}

fn optional_requirement(required: bool, satisfied: bool) -> bool {
    !required || satisfied
}

fn observed_height_for(config: &Config, kind: ReceiptLaneKind, offset: u64) -> u64 {
    let base = match kind {
        ReceiptLaneKind::WalletScanTranscript | ReceiptLaneKind::WalletRecoveryTranscript => {
            config.wallet_scan_height
        }
        ReceiptLaneKind::WatchtowerReplayReceipt | ReceiptLaneKind::WatchtowerQuorumAttestation => {
            config.watchtower_replay_height
        }
        ReceiptLaneKind::ReleasePolicyBinding
        | ReceiptLaneKind::FreshnessHold
        | ReceiptLaneKind::MismatchHold => config.release_policy_height,
    };
    base.saturating_add(offset)
}

fn default_lane_count(kind: ReceiptLaneKind) -> u64 {
    match kind {
        ReceiptLaneKind::WalletScanTranscript => DEFAULT_MIN_WALLET_TRANSCRIPTS,
        ReceiptLaneKind::WalletRecoveryTranscript => DEFAULT_MIN_RECOVERY_EVIDENCE,
        ReceiptLaneKind::WatchtowerReplayReceipt => DEFAULT_MIN_LIVE_RECEIPTS,
        ReceiptLaneKind::WatchtowerQuorumAttestation => DEFAULT_MIN_WATCHTOWER_QUORUM,
        ReceiptLaneKind::ReleasePolicyBinding => 2,
        ReceiptLaneKind::FreshnessHold | ReceiptLaneKind::MismatchHold => 0,
    }
}

fn state_from_parts(config: Config, lanes: Vec<ReceiptLane>) -> State {
    let counters = counters(&config, &lanes);
    let mut roots = Roots {
        wallet_scan_transcript_root: lane_kind_root(&lanes, ReceiptLaneKind::WalletScanTranscript),
        wallet_recovery_transcript_root: lane_kind_root(
            &lanes,
            ReceiptLaneKind::WalletRecoveryTranscript,
        ),
        wallet_transcript_root: combined_root(
            "wallet-transcripts",
            &[
                lane_kind_root(&lanes, ReceiptLaneKind::WalletScanTranscript),
                lane_kind_root(&lanes, ReceiptLaneKind::WalletRecoveryTranscript),
            ],
        ),
        watchtower_replay_receipt_root: lane_kind_root(
            &lanes,
            ReceiptLaneKind::WatchtowerReplayReceipt,
        ),
        watchtower_quorum_attestation_root: lane_kind_root(
            &lanes,
            ReceiptLaneKind::WatchtowerQuorumAttestation,
        ),
        watchtower_quorum_root: combined_root(
            "watchtower-quorum",
            &[
                lane_kind_root(&lanes, ReceiptLaneKind::WatchtowerReplayReceipt),
                lane_kind_root(&lanes, ReceiptLaneKind::WatchtowerQuorumAttestation),
            ],
        ),
        recovery_evidence_root: component_collection_root("recovery-evidence", &lanes, |lane| {
            &lane.recovery_evidence_root
        }),
        live_receipt_root: component_collection_root("live-receipts", &lanes, |lane| {
            &lane.live_receipt_root
        }),
        release_policy_binding_root: component_collection_root(
            "release-policy-bindings",
            &lanes,
            |lane| &lane.policy_binding_root,
        ),
        mismatch_hold_root: status_root(&lanes, EvidenceStatus::Mismatch),
        freshness_hold_root: freshness_hold_root(&config, &lanes),
        lane_commitment_root: lane_commitment_root(&lanes),
        activation_verdict_root: String::new(),
        state_commitment_root: String::new(),
    };
    let verdict = ActivationVerdict::new(&config, &roots, &counters);
    roots.activation_verdict_root = verdict.state_root();
    roots.state_commitment_root = state_commitment_root(&config, &roots, &counters, &verdict);
    State {
        config,
        lanes,
        roots,
        counters,
        verdict,
    }
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
