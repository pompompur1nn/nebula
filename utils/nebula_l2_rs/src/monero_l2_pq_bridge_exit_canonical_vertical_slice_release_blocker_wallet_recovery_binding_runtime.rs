use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerWalletRecoveryBindingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_WALLET_RECOVERY_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-wallet-recovery-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_WALLET_RECOVERY_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BINDING_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-release-blocker-wallet-recovery-binding-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_RELEASE_CANDIDATE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-wallet-recovery-binding-release-candidate-devnet-v1";
pub const DEFAULT_RECOVERY_EPOCH: u64 = 9;
pub const DEFAULT_MIN_SCAN_EXPORTS: u16 = 3;
pub const DEFAULT_MIN_RECEIPT_CONFIRMATIONS: u64 = 12;
pub const DEFAULT_MIN_LIVE_FEED_QUORUM: u16 = 4;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_PRIVACY_LEAKAGE_UNITS: u16 = 2;
pub const REQUIRED_BLOCKER_LANES: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerLane {
    WalletScanExports,
    PrivateNoteRecovery,
    ForcedExitClaimConstruction,
    PqWithdrawalAuthority,
    ObservedReceipts,
    LiveFeeds,
    PrivacySurfaces,
    ProductionGates,
}

impl BlockerLane {
    pub fn all() -> [Self; REQUIRED_BLOCKER_LANES] {
        [
            Self::WalletScanExports,
            Self::PrivateNoteRecovery,
            Self::ForcedExitClaimConstruction,
            Self::PqWithdrawalAuthority,
            Self::ObservedReceipts,
            Self::LiveFeeds,
            Self::PrivacySurfaces,
            Self::ProductionGates,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScanExports => "wallet_scan_exports",
            Self::PrivateNoteRecovery => "private_note_recovery",
            Self::ForcedExitClaimConstruction => "forced_exit_claim_construction",
            Self::PqWithdrawalAuthority => "pq_withdrawal_authority",
            Self::ObservedReceipts => "observed_receipts",
            Self::LiveFeeds => "live_feeds",
            Self::PrivacySurfaces => "privacy_surfaces",
            Self::ProductionGates => "production_gates",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    WalletScanExport,
    RecoveryViewKeyBinding,
    PrivateNoteReconstruction,
    NullifierBinding,
    ForcedExitClaim,
    PqWithdrawalAuthorization,
    ObservedReceipt,
    LiveFeedObservation,
    PrivacySurfaceReview,
    ProductionGateAttestation,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScanExport => "wallet_scan_export",
            Self::RecoveryViewKeyBinding => "recovery_view_key_binding",
            Self::PrivateNoteReconstruction => "private_note_reconstruction",
            Self::NullifierBinding => "nullifier_binding",
            Self::ForcedExitClaim => "forced_exit_claim",
            Self::PqWithdrawalAuthorization => "pq_withdrawal_authorization",
            Self::ObservedReceipt => "observed_receipt",
            Self::LiveFeedObservation => "live_feed_observation",
            Self::PrivacySurfaceReview => "privacy_surface_review",
            Self::ProductionGateAttestation => "production_gate_attestation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Bound,
    Recovered,
    Missing,
    Mismatched,
    Stale,
    HoldOpen,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Recovered => "recovered",
            Self::Missing => "missing",
            Self::Mismatched => "mismatched",
            Self::Stale => "stale",
            Self::HoldOpen => "hold_open",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(
            self,
            Self::Missing | Self::Mismatched | Self::Stale | Self::HoldOpen
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    Informational,
    Watch,
    Major,
    Critical,
    ReleaseStop,
}

impl BlockerSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Watch => "watch",
            Self::Major => "major",
            Self::Critical => "critical",
            Self::ReleaseStop => "release_stop",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Informational => 1,
            Self::Watch => 2,
            Self::Major => 3,
            Self::Critical => 4,
            Self::ReleaseStop => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerStatus {
    Clear,
    EvidenceMissing,
    EvidenceMismatched,
    PrivacyHold,
    PqHold,
    ReceiptHold,
    LiveFeedHold,
    ProductionHold,
}

impl BlockerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::EvidenceMissing => "evidence_missing",
            Self::EvidenceMismatched => "evidence_mismatched",
            Self::PrivacyHold => "privacy_hold",
            Self::PqHold => "pq_hold",
            Self::ReceiptHold => "receipt_hold",
            Self::LiveFeedHold => "live_feed_hold",
            Self::ProductionHold => "production_hold",
        }
    }

    pub fn blocks_release(self) -> bool {
        self != Self::Clear
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionDecision {
    Go,
    Hold,
    NoGo,
}

impl ProductionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Hold => "hold",
            Self::NoGo => "no_go",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub binding_suite: String,
    pub vertical_slice_id: String,
    pub release_candidate_id: String,
    pub recovery_epoch: u64,
    pub min_scan_exports: u16,
    pub min_receipt_confirmations: u64,
    pub min_live_feed_quorum: u16,
    pub min_pq_security_bits: u16,
    pub max_privacy_leakage_units: u16,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            binding_suite: BINDING_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            release_candidate_id: DEFAULT_RELEASE_CANDIDATE_ID.to_string(),
            recovery_epoch: DEFAULT_RECOVERY_EPOCH,
            min_scan_exports: DEFAULT_MIN_SCAN_EXPORTS,
            min_receipt_confirmations: DEFAULT_MIN_RECEIPT_CONFIRMATIONS,
            min_live_feed_quorum: DEFAULT_MIN_LIVE_FEED_QUORUM,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_privacy_leakage_units: DEFAULT_MAX_PRIVACY_LEAKAGE_UNITS,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "binding_suite": self.binding_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "release_candidate_id": self.release_candidate_id,
            "recovery_epoch": self.recovery_epoch,
            "min_scan_exports": self.min_scan_exports,
            "min_receipt_confirmations": self.min_receipt_confirmations,
            "min_live_feed_quorum": self.min_live_feed_quorum,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_privacy_leakage_units": self.max_privacy_leakage_units,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoverySubject {
    pub wallet_id: String,
    pub account_index: u32,
    pub recovery_session_id: String,
    pub note_commitment: String,
    pub nullifier_commitment: String,
    pub forced_exit_claim_id: String,
    pub scan_window_start: u64,
    pub scan_window_end: u64,
}

impl RecoverySubject {
    pub fn devnet(config: &Config) -> Self {
        let wallet_id = short_hash("WALLET", &[HashPart::Str(&config.release_candidate_id)]);
        let recovery_session_id = short_hash(
            "RECOVERY-SESSION",
            &[
                HashPart::Str(&wallet_id),
                HashPart::Int(config.recovery_epoch as i128),
            ],
        );
        let note_commitment = commitment("NOTE", &recovery_session_id, 0);
        let nullifier_commitment = commitment("NULLIFIER", &recovery_session_id, 1);
        let forced_exit_claim_id = short_hash(
            "FORCED-EXIT-CLAIM",
            &[
                HashPart::Str(&recovery_session_id),
                HashPart::Str(&note_commitment),
            ],
        );

        Self {
            wallet_id,
            account_index: 0,
            recovery_session_id,
            note_commitment,
            nullifier_commitment,
            forced_exit_claim_id,
            scan_window_start: 879_840,
            scan_window_end: 880_080,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "wallet_id": self.wallet_id,
            "account_index": self.account_index,
            "recovery_session_id": self.recovery_session_id,
            "note_commitment": self.note_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "forced_exit_claim_id": self.forced_exit_claim_id,
            "scan_window_start": self.scan_window_start,
            "scan_window_end": self.scan_window_end,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("RECOVERY-SUBJECT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BindingEvidence {
    pub evidence_id: String,
    pub lane: BlockerLane,
    pub kind: EvidenceKind,
    pub status: EvidenceStatus,
    pub severity: BlockerSeverity,
    pub source: String,
    pub expected_root: String,
    pub observed_root: String,
    pub observed_height: u64,
    pub required_confirmations: u64,
    pub observed_confirmations: u64,
    pub quorum: u16,
    pub required_quorum: u16,
    pub pq_security_bits: u16,
    pub privacy_leakage_units: u16,
    pub missing_fields: Vec<String>,
    pub mismatched_fields: Vec<String>,
    pub clearance_requirement: String,
}

impl BindingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "lane": self.lane.as_str(),
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "severity_score": self.severity.score(),
            "source": self.source,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "observed_height": self.observed_height,
            "required_confirmations": self.required_confirmations,
            "observed_confirmations": self.observed_confirmations,
            "quorum": self.quorum,
            "required_quorum": self.required_quorum,
            "pq_security_bits": self.pq_security_bits,
            "privacy_leakage_units": self.privacy_leakage_units,
            "missing_fields": self.missing_fields,
            "mismatched_fields": self.mismatched_fields,
            "clearance_requirement": self.clearance_requirement,
            "blocks_release": self.status.blocks_release(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("BINDING-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneBlocker {
    pub lane: BlockerLane,
    pub status: BlockerStatus,
    pub severity: BlockerSeverity,
    pub evidence_ids: Vec<String>,
    pub evidence_root: String,
    pub missing_count: u64,
    pub mismatch_count: u64,
    pub privacy_hold_count: u64,
    pub pq_hold_count: u64,
    pub receipt_hold_count: u64,
    pub live_feed_hold_count: u64,
    pub release_condition: String,
}

impl LaneBlocker {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "severity_score": self.severity.score(),
            "evidence_ids": self.evidence_ids,
            "evidence_root": self.evidence_root,
            "missing_count": self.missing_count,
            "mismatch_count": self.mismatch_count,
            "privacy_hold_count": self.privacy_hold_count,
            "pq_hold_count": self.pq_hold_count,
            "receipt_hold_count": self.receipt_hold_count,
            "live_feed_hold_count": self.live_feed_hold_count,
            "release_condition": self.release_condition,
            "blocks_release": self.status.blocks_release(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("LANE-BLOCKER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionGate {
    pub gate_id: String,
    pub decision: ProductionDecision,
    pub open_blockers: u64,
    pub release_stop_blockers: u64,
    pub missing_evidence_total: u64,
    pub mismatch_evidence_total: u64,
    pub privacy_hold_total: u64,
    pub pq_hold_total: u64,
    pub observed_receipt_hold_total: u64,
    pub live_feed_hold_total: u64,
    pub lane_root: String,
    pub evidence_root: String,
    pub reason: String,
}

impl ProductionGate {
    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "decision": self.decision.as_str(),
            "open_blockers": self.open_blockers,
            "release_stop_blockers": self.release_stop_blockers,
            "missing_evidence_total": self.missing_evidence_total,
            "mismatch_evidence_total": self.mismatch_evidence_total,
            "privacy_hold_total": self.privacy_hold_total,
            "pq_hold_total": self.pq_hold_total,
            "observed_receipt_hold_total": self.observed_receipt_hold_total,
            "live_feed_hold_total": self.live_feed_hold_total,
            "lane_root": self.lane_root,
            "evidence_root": self.evidence_root,
            "reason": self.reason,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PRODUCTION-GATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub subject: RecoverySubject,
    pub evidence: Vec<BindingEvidence>,
    pub lane_blockers: Vec<LaneBlocker>,
    pub severity_counts: BTreeMap<String, u64>,
    pub lane_roots: BTreeMap<String, String>,
    pub production_gate: ProductionGate,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let subject = RecoverySubject::devnet(&config);
        let evidence = devnet_evidence(&config, &subject);
        let lane_blockers = build_lane_blockers(&evidence);
        let evidence_root = list_root(
            "BINDING-EVIDENCE-LIST",
            evidence.iter().map(|item| item.state_root()),
        );
        let lane_root = list_root(
            "LANE-BLOCKER-LIST",
            lane_blockers.iter().map(|item| item.state_root()),
        );
        let severity_counts = severity_counts(&lane_blockers);
        let lane_roots = lane_roots(&lane_blockers);
        let production_gate =
            build_production_gate(&config, &lane_blockers, &evidence_root, &lane_root);

        Self {
            config,
            subject,
            evidence,
            lane_blockers,
            severity_counts,
            lane_roots,
            production_gate,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "subject": self.subject.public_record(),
            "evidence": self.evidence.iter().map(|item| item.public_record()).collect::<Vec<_>>(),
            "lane_blockers": self.lane_blockers.iter().map(|item| item.public_record()).collect::<Vec<_>>(),
            "severity_counts": self.severity_counts,
            "lane_roots": self.lane_roots,
            "production_gate": self.production_gate.public_record(),
            "roots": {
                "config_root": self.config.state_root(),
                "subject_root": self.subject.state_root(),
                "evidence_root": list_root("BINDING-EVIDENCE-LIST", self.evidence.iter().map(|item| item.state_root())),
                "lane_root": list_root("LANE-BLOCKER-LIST", self.lane_blockers.iter().map(|item| item.state_root())),
                "production_gate_root": self.production_gate.state_root(),
            }
        })
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record())
    }

    pub fn open_blockers(&self) -> Vec<&LaneBlocker> {
        self.lane_blockers
            .iter()
            .filter(|item| item.status.blocks_release())
            .collect::<Vec<_>>()
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

#[rustfmt::skip]
fn devnet_evidence(config: &Config, subject: &RecoverySubject) -> Vec<BindingEvidence> {
    let rows = [
        (BlockerLane::WalletScanExports, EvidenceKind::WalletScanExport, EvidenceStatus::Bound, BlockerSeverity::Informational, "wallet-scan-exporter-devnet", 4, config.min_scan_exports, 0, 0, &[][..], &[][..]),
        (BlockerLane::WalletScanExports, EvidenceKind::RecoveryViewKeyBinding, EvidenceStatus::Mismatched, BlockerSeverity::Critical, "watch-only-recovery-binder-devnet", 2, config.min_scan_exports, 0, 0, &[][..], &["view_key_commitment", "scan_export_epoch"][..]),
        (BlockerLane::PrivateNoteRecovery, EvidenceKind::PrivateNoteReconstruction, EvidenceStatus::Recovered, BlockerSeverity::Watch, "private-note-recovery-devnet", 1, 1, 0, 0, &[][..], &[][..]),
        (BlockerLane::PrivateNoteRecovery, EvidenceKind::NullifierBinding, EvidenceStatus::Missing, BlockerSeverity::ReleaseStop, "nullifier-binding-cache-devnet", 0, 1, 0, 0, &["nullifier_secret_share", "key_image_binding"][..], &[][..]),
        (BlockerLane::ForcedExitClaimConstruction, EvidenceKind::ForcedExitClaim, EvidenceStatus::HoldOpen, BlockerSeverity::Critical, "forced-exit-claim-builder-devnet", 1, 1, 0, 0, &["claim_witness_bundle"][..], &["claim_amount_commitment"][..]),
        (BlockerLane::PqWithdrawalAuthority, EvidenceKind::PqWithdrawalAuthorization, EvidenceStatus::HoldOpen, BlockerSeverity::ReleaseStop, "pq-withdrawal-authority-devnet", config.min_live_feed_quorum - 1, config.min_live_feed_quorum, config.min_pq_security_bits, 0, &["authority_rotation_signoff"][..], &[][..]),
        (BlockerLane::ObservedReceipts, EvidenceKind::ObservedReceipt, EvidenceStatus::Stale, BlockerSeverity::Major, "observed-receipt-ingest-devnet", 3, 3, 0, 0, &[][..], &["receipt_height", "receipt_merkle_path"][..]),
        (BlockerLane::LiveFeeds, EvidenceKind::LiveFeedObservation, EvidenceStatus::Missing, BlockerSeverity::Critical, "release-blocker-live-feed-devnet", config.min_live_feed_quorum - 2, config.min_live_feed_quorum, 0, 0, &["monero_header_feed", "reserve_liquidity_feed"][..], &[][..]),
        (BlockerLane::PrivacySurfaces, EvidenceKind::PrivacySurfaceReview, EvidenceStatus::HoldOpen, BlockerSeverity::ReleaseStop, "privacy-surface-review-devnet", 1, 1, 0, config.max_privacy_leakage_units + 1, &["redacted_scan_hint_manifest"][..], &["timing_bucket", "wallet_label_redaction"][..]),
        (BlockerLane::ProductionGates, EvidenceKind::ProductionGateAttestation, EvidenceStatus::HoldOpen, BlockerSeverity::ReleaseStop, "production-gate-attestor-devnet", 0, 1, 0, 0, &["operator_go_attestation", "audit_signoff"][..], &[][..]),
    ];

    rows.iter()
        .enumerate()
        .map(
            |(
                index,
                (
                    lane,
                    kind,
                    status,
                    severity,
                    source,
                    quorum,
                    required_quorum,
                    pq_security_bits,
                    privacy_leakage_units,
                    missing_fields,
                    mismatched_fields,
                ),
            )| {
                make_evidence(
                    config,
                    subject,
                    index as u64,
                    *lane,
                    *kind,
                    *status,
                    *severity,
                    source,
                    *quorum,
                    *required_quorum,
                    *pq_security_bits,
                    *privacy_leakage_units,
                    missing_fields,
                    mismatched_fields,
                )
            },
        )
        .collect::<Vec<_>>()
}

fn make_evidence(
    config: &Config,
    subject: &RecoverySubject,
    sequence: u64,
    lane: BlockerLane,
    kind: EvidenceKind,
    status: EvidenceStatus,
    severity: BlockerSeverity,
    source: &str,
    quorum: u16,
    required_quorum: u16,
    pq_security_bits: u16,
    privacy_leakage_units: u16,
    missing_fields: &[&str],
    mismatched_fields: &[&str],
) -> BindingEvidence {
    let evidence_id = short_hash(
        "BINDING-EVIDENCE-ID",
        &[
            HashPart::Str(&subject.recovery_session_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Int(sequence as i128),
        ],
    );
    let expected_root = domain_hash(
        "WALLET-RECOVERY-BINDING-EXPECTED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.release_candidate_id),
            HashPart::Str(&subject.note_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Str(kind.as_str()),
        ],
        32,
    );
    let observed_root = if status == EvidenceStatus::Bound || status == EvidenceStatus::Recovered {
        expected_root.clone()
    } else {
        domain_hash(
            "WALLET-RECOVERY-BINDING-OBSERVED",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&evidence_id),
                HashPart::Str(status.as_str()),
                HashPart::Int(sequence as i128),
            ],
            32,
        )
    };

    BindingEvidence {
        evidence_id,
        lane,
        kind,
        status,
        severity,
        source: source.to_string(),
        expected_root,
        observed_root,
        observed_height: 880_000 + sequence,
        required_confirmations: config.min_receipt_confirmations,
        observed_confirmations: observed_confirmations(lane, status, config),
        quorum,
        required_quorum,
        pq_security_bits,
        privacy_leakage_units,
        missing_fields: missing_fields
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<_>>(),
        mismatched_fields: mismatched_fields
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<_>>(),
        clearance_requirement: clearance_requirement(lane, status).to_string(),
    }
}

fn build_lane_blockers(evidence: &[BindingEvidence]) -> Vec<LaneBlocker> {
    BlockerLane::all()
        .iter()
        .map(|lane| {
            let lane_evidence = evidence
                .iter()
                .filter(|item| item.lane == *lane)
                .collect::<Vec<_>>();
            let roots = lane_evidence
                .iter()
                .map(|item| item.state_root())
                .collect::<Vec<_>>();
            let evidence_ids = lane_evidence
                .iter()
                .map(|item| item.evidence_id.clone())
                .collect::<Vec<_>>();
            let missing_count = lane_evidence
                .iter()
                .filter(|item| item.status == EvidenceStatus::Missing)
                .count() as u64;
            let mismatch_count = lane_evidence
                .iter()
                .filter(|item| item.status == EvidenceStatus::Mismatched)
                .count() as u64;
            let privacy_hold_count = lane_evidence
                .iter()
                .filter(|item| {
                    item.lane == BlockerLane::PrivacySurfaces
                        && (item.status == EvidenceStatus::HoldOpen
                            || item.privacy_leakage_units > DEFAULT_MAX_PRIVACY_LEAKAGE_UNITS)
                })
                .count() as u64;
            let pq_hold_count = lane_evidence
                .iter()
                .filter(|item| {
                    item.lane == BlockerLane::PqWithdrawalAuthority
                        && (item.status == EvidenceStatus::HoldOpen
                            || item.pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS)
                })
                .count() as u64;
            let receipt_hold_count = lane_evidence
                .iter()
                .filter(|item| {
                    item.lane == BlockerLane::ObservedReceipts
                        && item.observed_confirmations < item.required_confirmations
                })
                .count() as u64;
            let live_feed_hold_count = lane_evidence
                .iter()
                .filter(|item| {
                    item.lane == BlockerLane::LiveFeeds && item.quorum < item.required_quorum
                })
                .count() as u64;
            let severity = lane_evidence
                .iter()
                .map(|item| item.severity)
                .max()
                .unwrap_or(BlockerSeverity::Informational);
            let status = lane_status(
                *lane,
                missing_count,
                mismatch_count,
                privacy_hold_count,
                pq_hold_count,
                receipt_hold_count,
                live_feed_hold_count,
                lane_evidence
                    .iter()
                    .any(|item| item.status == EvidenceStatus::HoldOpen),
            );

            LaneBlocker {
                lane: *lane,
                status,
                severity,
                evidence_ids,
                evidence_root: merkle_root(&roots),
                missing_count,
                mismatch_count,
                privacy_hold_count,
                pq_hold_count,
                receipt_hold_count,
                live_feed_hold_count,
                release_condition: lane_release_condition(*lane, status).to_string(),
            }
        })
        .collect::<Vec<_>>()
}

fn build_production_gate(
    config: &Config,
    lane_blockers: &[LaneBlocker],
    evidence_root: &str,
    lane_root: &str,
) -> ProductionGate {
    let open_blockers = lane_blockers
        .iter()
        .filter(|item| item.status.blocks_release())
        .count() as u64;
    let release_stop_blockers = lane_blockers
        .iter()
        .filter(|item| {
            item.status.blocks_release() && item.severity == BlockerSeverity::ReleaseStop
        })
        .count() as u64;
    let missing_evidence_total = lane_blockers
        .iter()
        .map(|item| item.missing_count)
        .sum::<u64>();
    let mismatch_evidence_total = lane_blockers
        .iter()
        .map(|item| item.mismatch_count)
        .sum::<u64>();
    let privacy_hold_total = lane_blockers
        .iter()
        .map(|item| item.privacy_hold_count)
        .sum::<u64>();
    let pq_hold_total = lane_blockers
        .iter()
        .map(|item| item.pq_hold_count)
        .sum::<u64>();
    let observed_receipt_hold_total = lane_blockers
        .iter()
        .map(|item| item.receipt_hold_count)
        .sum::<u64>();
    let live_feed_hold_total = lane_blockers
        .iter()
        .map(|item| item.live_feed_hold_count)
        .sum::<u64>();
    let decision = if release_stop_blockers > 0 || !config.production_release_allowed {
        ProductionDecision::NoGo
    } else if open_blockers > 0 {
        ProductionDecision::Hold
    } else {
        ProductionDecision::Go
    };

    ProductionGate {
        gate_id: short_hash(
            "WALLET-RECOVERY-BINDING-PRODUCTION-GATE",
            &[
                HashPart::Str(&config.release_candidate_id),
                HashPart::Str(evidence_root),
                HashPart::Str(lane_root),
            ],
        ),
        decision,
        open_blockers,
        release_stop_blockers,
        missing_evidence_total,
        mismatch_evidence_total,
        privacy_hold_total,
        pq_hold_total,
        observed_receipt_hold_total,
        live_feed_hold_total,
        lane_root: lane_root.to_string(),
        evidence_root: evidence_root.to_string(),
        reason: production_reason(
            decision,
            open_blockers,
            release_stop_blockers,
            missing_evidence_total,
            mismatch_evidence_total,
            privacy_hold_total,
            pq_hold_total,
            observed_receipt_hold_total,
            live_feed_hold_total,
            config.production_release_allowed,
        ),
    }
}

fn lane_status(
    lane: BlockerLane,
    missing_count: u64,
    mismatch_count: u64,
    privacy_hold_count: u64,
    pq_hold_count: u64,
    receipt_hold_count: u64,
    live_feed_hold_count: u64,
    hold_open: bool,
) -> BlockerStatus {
    if missing_count > 0 {
        return BlockerStatus::EvidenceMissing;
    }
    if mismatch_count > 0 {
        return BlockerStatus::EvidenceMismatched;
    }
    if privacy_hold_count > 0 {
        return BlockerStatus::PrivacyHold;
    }
    if pq_hold_count > 0 {
        return BlockerStatus::PqHold;
    }
    if receipt_hold_count > 0 {
        return BlockerStatus::ReceiptHold;
    }
    if live_feed_hold_count > 0 {
        return BlockerStatus::LiveFeedHold;
    }
    if lane == BlockerLane::ProductionGates && hold_open {
        return BlockerStatus::ProductionHold;
    }
    if hold_open {
        return match lane {
            BlockerLane::PqWithdrawalAuthority => BlockerStatus::PqHold,
            BlockerLane::PrivacySurfaces => BlockerStatus::PrivacyHold,
            BlockerLane::ObservedReceipts => BlockerStatus::ReceiptHold,
            BlockerLane::LiveFeeds => BlockerStatus::LiveFeedHold,
            BlockerLane::ProductionGates => BlockerStatus::ProductionHold,
            _ => BlockerStatus::EvidenceMissing,
        };
    }
    BlockerStatus::Clear
}

fn severity_counts(lane_blockers: &[LaneBlocker]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for blocker in lane_blockers {
        let entry = counts
            .entry(blocker.severity.as_str().to_string())
            .or_insert(0);
        *entry += 1;
    }
    counts
}

fn lane_roots(lane_blockers: &[LaneBlocker]) -> BTreeMap<String, String> {
    lane_blockers
        .iter()
        .map(|item| (item.lane.as_str().to_string(), item.state_root()))
        .collect::<BTreeMap<_, _>>()
}

fn observed_confirmations(lane: BlockerLane, status: EvidenceStatus, config: &Config) -> u64 {
    if status == EvidenceStatus::Stale {
        return config.min_receipt_confirmations - 4;
    }
    if lane == BlockerLane::ObservedReceipts && status.blocks_release() {
        return config.min_receipt_confirmations - 1;
    }
    config.min_receipt_confirmations
}

fn lane_release_condition(lane: BlockerLane, status: BlockerStatus) -> &'static str {
    match (lane, status) {
        (_, BlockerStatus::Clear) => "retain bound wallet-recovery evidence in release record",
        (BlockerLane::WalletScanExports, BlockerStatus::EvidenceMismatched) => {
            "re-export wallet scan bundle and bind recovery view key root to canonical session"
        }
        (BlockerLane::WalletScanExports, _) => {
            "attach complete wallet scan export quorum before release"
        }
        (BlockerLane::PrivateNoteRecovery, _) => {
            "recover private note, nullifier secret share, and key-image binding"
        }
        (BlockerLane::ForcedExitClaimConstruction, _) => {
            "rebuild forced-exit claim with note, nullifier, amount, and witness roots"
        }
        (BlockerLane::PqWithdrawalAuthority, _) => {
            "clear pq withdrawal authority hold and publish quorum rotation signoff"
        }
        (BlockerLane::ObservedReceipts, _) => {
            "ingest fresh observed receipt with canonical merkle path and confirmations"
        }
        (BlockerLane::LiveFeeds, _) => {
            "restore live feed quorum for monero headers, reserves, and release-blocker lanes"
        }
        (BlockerLane::PrivacySurfaces, _) => {
            "complete redaction review with leakage units below configured maximum"
        }
        (BlockerLane::ProductionGates, _) => {
            "collect operator go attestation, audit signoff, and production release approval"
        }
    }
}

fn clearance_requirement(lane: BlockerLane, status: EvidenceStatus) -> &'static str {
    match (lane, status) {
        (_, EvidenceStatus::Bound) | (_, EvidenceStatus::Recovered) => {
            "retain evidence root in wallet-recovery binding manifest"
        }
        (BlockerLane::WalletScanExports, EvidenceStatus::Mismatched) => {
            "rerun scan export and compare expected recovery-session root"
        }
        (BlockerLane::WalletScanExports, _) => {
            "provide missing scan export shard and view-key binding"
        }
        (BlockerLane::PrivateNoteRecovery, _) => {
            "restore private note recovery material without widening public metadata"
        }
        (BlockerLane::ForcedExitClaimConstruction, _) => {
            "reconstruct forced-exit claim witness bundle and replay claim builder"
        }
        (BlockerLane::PqWithdrawalAuthority, _) => {
            "refresh pq authorization quorum with current withdrawal authority root"
        }
        (BlockerLane::ObservedReceipts, _) => {
            "refresh observed receipt ingest from canonical chain source"
        }
        (BlockerLane::LiveFeeds, _) => "restore live feed observation quorum and replay feed roots",
        (BlockerLane::PrivacySurfaces, _) => {
            "publish privacy review root with redacted scan hints and bounded leakage"
        }
        (BlockerLane::ProductionGates, _) => {
            "record production gate attestation only after all blocker lanes clear"
        }
    }
}

fn production_reason(
    decision: ProductionDecision,
    open_blockers: u64,
    release_stop_blockers: u64,
    missing: u64,
    mismatched: u64,
    privacy_holds: u64,
    pq_holds: u64,
    receipt_holds: u64,
    live_feed_holds: u64,
    production_release_allowed: bool,
) -> String {
    if !production_release_allowed {
        return format!(
            "production no-go: release flag disabled with {} open wallet-recovery binding blockers",
            open_blockers
        );
    }
    match decision {
        ProductionDecision::Go => {
            "production go: all wallet-recovery binding lanes are clear".to_string()
        }
        ProductionDecision::Hold => format!(
            "production hold: {} open blockers, {} missing, {} mismatched, {} privacy holds, {} pq holds, {} receipt holds, {} live-feed holds",
            open_blockers, missing, mismatched, privacy_holds, pq_holds, receipt_holds, live_feed_holds
        ),
        ProductionDecision::NoGo => format!(
            "production no-go: {} release-stop blockers across wallet-recovery binding evidence",
            release_stop_blockers
        ),
    }
}

fn commitment(label: &str, recovery_session_id: &str, sequence: u64) -> String {
    domain_hash(
        "WALLET-RECOVERY-BINDING-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(recovery_session_id),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn short_hash(label: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(label, parts, 16)
}

fn list_root<I>(label: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let items = roots.into_iter().collect::<Vec<_>>();
    domain_hash(
        "WALLET-RECOVERY-BINDING-LIST",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(&merkle_root(&items)),
            HashPart::Int(items.len() as i128),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "WALLET-RECOVERY-BINDING-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
