use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2WatcherEvidenceLaneResult<T> = Result<T, String>;

pub const MONERO_L2_WATCHER_EVIDENCE_LANE_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-watcher-evidence-lane-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_WATCHER_EVIDENCE_LANE_PROTOCOL_VERSION;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_DEVNET_COMMITTEE_ID: &str =
    "monero-l2-watcher-evidence-lane-devnet-committee";
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_DEVNET_HEIGHT: u64 = 24_600;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_HEADER_ROOT_SCHEME: &str =
    "monero-header-chain-root-shake256-v1";
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_TXSET_ROOT_SCHEME: &str =
    "monero-txset-roots-only-shake256-v1";
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_REORG_EVIDENCE_SCHEME: &str =
    "monero-reorg-evidence-roots-only-v1";
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_PQ_SIGNATURE_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192f-watcher-evidence-v1";
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_DISCLOSURE_SCHEME: &str =
    "selective-disclosure-roots-only-v1";
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_CHALLENGE_SCHEME: &str =
    "watcher-evidence-challenge-window-v1";
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_RECEIPT_SCHEME: &str =
    "watcher-fraud-evidence-receipt-v1";
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_BATCH_SCHEME: &str = "monero-finality-evidence-batch-v1";
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_FINALITY_DEPTH: u64 = 20;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_REORG_ALERT_DEPTH: u64 = 12;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_REORG_SLASH_DEPTH: u64 = 32;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_MIN_WATCHER_WEIGHT: u64 = 3;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_MIN_DISCLOSURE_COUNT: u64 = 1;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_MAX_BATCH_SIZE: usize = 128;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_MAX_EVIDENCE: usize = 262_144;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_MAX_RECEIPTS: usize = 262_144;
pub const MONERO_L2_WATCHER_EVIDENCE_LANE_MAX_BATCHES: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    HeaderRoot,
    TxsetRoot,
    Reorg,
    PqSignature,
    SelectiveDisclosure,
    FinalityFraud,
    BridgeSafety,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderRoot => "header_root",
            Self::TxsetRoot => "txset_root",
            Self::Reorg => "reorg",
            Self::PqSignature => "pq_signature",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::FinalityFraud => "finality_fraud",
            Self::BridgeSafety => "bridge_safety",
        }
    }

    pub fn high_severity(self) -> bool {
        matches!(self, Self::Reorg | Self::FinalityFraud | Self::BridgeSafety)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Submitted,
    ChallengeOpen,
    Challenged,
    Accepted,
    Rejected,
    Expired,
    Batched,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::ChallengeOpen => "challenge_open",
            Self::Challenged => "challenged",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Batched => "batched",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::Rejected | Self::Expired | Self::Batched
        )
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Accepted | Self::ChallengeOpen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Sustained,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sustained => "sustained",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Sustained | Self::Rejected | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Submitted,
    ChallengeOpened,
    ChallengeResolved,
    Accepted,
    Rejected,
    Batched,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::ChallengeOpened => "challenge_opened",
            Self::ChallengeResolved => "challenge_resolved",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Batched => "batched",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Built,
    Submitted,
    Finalized,
    Disputed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Submitted => "submitted",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroL2WatcherEvidenceLaneConfig {
    pub network: String,
    pub asset_id: String,
    pub committee_id: String,
    pub challenge_window_blocks: u64,
    pub finality_depth: u64,
    pub reorg_alert_depth: u64,
    pub reorg_slash_depth: u64,
    pub min_watcher_weight: u64,
    pub min_disclosure_count: u64,
    pub max_batch_size: usize,
    pub header_root_scheme: String,
    pub txset_root_scheme: String,
    pub reorg_evidence_scheme: String,
    pub pq_signature_scheme: String,
    pub disclosure_scheme: String,
    pub challenge_scheme: String,
    pub receipt_scheme: String,
    pub batch_scheme: String,
}

impl Default for MoneroL2WatcherEvidenceLaneConfig {
    fn default() -> Self {
        Self {
            network: MONERO_L2_WATCHER_EVIDENCE_LANE_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_L2_WATCHER_EVIDENCE_LANE_DEVNET_ASSET_ID.to_string(),
            committee_id: MONERO_L2_WATCHER_EVIDENCE_LANE_DEVNET_COMMITTEE_ID.to_string(),
            challenge_window_blocks:
                MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            finality_depth: MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_FINALITY_DEPTH,
            reorg_alert_depth: MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_REORG_ALERT_DEPTH,
            reorg_slash_depth: MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_REORG_SLASH_DEPTH,
            min_watcher_weight: MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_MIN_WATCHER_WEIGHT,
            min_disclosure_count: MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_MIN_DISCLOSURE_COUNT,
            max_batch_size: MONERO_L2_WATCHER_EVIDENCE_LANE_DEFAULT_MAX_BATCH_SIZE,
            header_root_scheme: MONERO_L2_WATCHER_EVIDENCE_LANE_HEADER_ROOT_SCHEME.to_string(),
            txset_root_scheme: MONERO_L2_WATCHER_EVIDENCE_LANE_TXSET_ROOT_SCHEME.to_string(),
            reorg_evidence_scheme: MONERO_L2_WATCHER_EVIDENCE_LANE_REORG_EVIDENCE_SCHEME
                .to_string(),
            pq_signature_scheme: MONERO_L2_WATCHER_EVIDENCE_LANE_PQ_SIGNATURE_SCHEME.to_string(),
            disclosure_scheme: MONERO_L2_WATCHER_EVIDENCE_LANE_DISCLOSURE_SCHEME.to_string(),
            challenge_scheme: MONERO_L2_WATCHER_EVIDENCE_LANE_CHALLENGE_SCHEME.to_string(),
            receipt_scheme: MONERO_L2_WATCHER_EVIDENCE_LANE_RECEIPT_SCHEME.to_string(),
            batch_scheme: MONERO_L2_WATCHER_EVIDENCE_LANE_BATCH_SCHEME.to_string(),
        }
    }
}

impl MoneroL2WatcherEvidenceLaneConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_WATCHER_EVIDENCE_LANE_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "network": self.network,
            "asset_id": self.asset_id,
            "committee_id": self.committee_id,
            "challenge_window_blocks": self.challenge_window_blocks,
            "finality_depth": self.finality_depth,
            "reorg_alert_depth": self.reorg_alert_depth,
            "reorg_slash_depth": self.reorg_slash_depth,
            "min_watcher_weight": self.min_watcher_weight,
            "min_disclosure_count": self.min_disclosure_count,
            "max_batch_size": self.max_batch_size,
            "header_root_scheme": self.header_root_scheme,
            "txset_root_scheme": self.txset_root_scheme,
            "reorg_evidence_scheme": self.reorg_evidence_scheme,
            "pq_signature_scheme": self.pq_signature_scheme,
            "disclosure_scheme": self.disclosure_scheme,
            "challenge_scheme": self.challenge_scheme,
            "receipt_scheme": self.receipt_scheme,
            "batch_scheme": self.batch_scheme,
        })
    }

    pub fn root(&self) -> String {
        lane_root("MONERO-L2-WATCHER-EVIDENCE-CONFIG", &self.public_record())
    }
}

pub type Config = MoneroL2WatcherEvidenceLaneConfig;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroL2WatcherEvidenceLaneCounters {
    pub next_evidence_sequence: u64,
    pub next_challenge_sequence: u64,
    pub next_receipt_sequence: u64,
    pub next_batch_sequence: u64,
    pub submitted_evidence: u64,
    pub accepted_evidence: u64,
    pub rejected_evidence: u64,
    pub challenged_evidence: u64,
    pub expired_evidence: u64,
    pub batches_built: u64,
}

impl MoneroL2WatcherEvidenceLaneCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_evidence_sequence": self.next_evidence_sequence,
            "next_challenge_sequence": self.next_challenge_sequence,
            "next_receipt_sequence": self.next_receipt_sequence,
            "next_batch_sequence": self.next_batch_sequence,
            "submitted_evidence": self.submitted_evidence,
            "accepted_evidence": self.accepted_evidence,
            "rejected_evidence": self.rejected_evidence,
            "challenged_evidence": self.challenged_evidence,
            "expired_evidence": self.expired_evidence,
            "batches_built": self.batches_built,
        })
    }
}

pub type Counters = MoneroL2WatcherEvidenceLaneCounters;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSubmission {
    pub kind: EvidenceKind,
    pub monero_height: u64,
    pub l2_height: u64,
    pub observed_at_height: u64,
    pub watcher_id: String,
    pub watcher_weight: u64,
    pub header_root: String,
    pub txset_root: String,
    pub reorg_evidence_root: String,
    pub pq_signature_root: String,
    pub selective_disclosure_root: String,
    pub finality_context_root: String,
    pub bridge_context_root: String,
    pub previous_evidence_root: String,
    pub evidence_nonce: String,
}

impl EvidenceSubmission {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "observed_at_height": self.observed_at_height,
            "watcher_id": self.watcher_id,
            "watcher_weight": self.watcher_weight,
            "header_root": self.header_root,
            "txset_root": self.txset_root,
            "reorg_evidence_root": self.reorg_evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "finality_context_root": self.finality_context_root,
            "bridge_context_root": self.bridge_context_root,
            "previous_evidence_root": self.previous_evidence_root,
            "evidence_nonce": self.evidence_nonce,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-WATCHER-EVIDENCE-SUBMISSION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherEvidence {
    pub evidence_id: String,
    pub sequence: u64,
    pub kind: EvidenceKind,
    pub status: EvidenceStatus,
    pub monero_height: u64,
    pub l2_height: u64,
    pub observed_at_height: u64,
    pub submitted_at_height: u64,
    pub challenge_deadline_height: u64,
    pub watcher_id: String,
    pub watcher_weight: u64,
    pub header_root: String,
    pub txset_root: String,
    pub reorg_evidence_root: String,
    pub pq_signature_root: String,
    pub selective_disclosure_root: String,
    pub finality_context_root: String,
    pub bridge_context_root: String,
    pub evidence_root: String,
    pub previous_evidence_root: String,
    pub challenge_root: String,
    pub receipt_root: String,
    pub batch_id: Option<String>,
}

impl WatcherEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "observed_at_height": self.observed_at_height,
            "submitted_at_height": self.submitted_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "watcher_id": self.watcher_id,
            "watcher_weight": self.watcher_weight,
            "header_root": self.header_root,
            "txset_root": self.txset_root,
            "reorg_evidence_root": self.reorg_evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "finality_context_root": self.finality_context_root,
            "bridge_context_root": self.bridge_context_root,
            "evidence_root": self.evidence_root,
            "previous_evidence_root": self.previous_evidence_root,
            "challenge_root": self.challenge_root,
            "receipt_root": self.receipt_root,
            "batch_id": self.batch_id,
        })
    }

    pub fn root(&self) -> String {
        lane_root("MONERO-L2-WATCHER-EVIDENCE", &self.public_record())
    }

    pub fn roots_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "header_root": self.header_root,
            "txset_root": self.txset_root,
            "reorg_evidence_root": self.reorg_evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "finality_context_root": self.finality_context_root,
            "bridge_context_root": self.bridge_context_root,
            "evidence_root": self.evidence_root,
            "challenge_root": self.challenge_root,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceChallenge {
    pub challenge_id: String,
    pub evidence_id: String,
    pub sequence: u64,
    pub status: ChallengeStatus,
    pub challenger_id: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub allegation_root: String,
    pub counter_evidence_root: String,
    pub pq_signature_root: String,
    pub selective_disclosure_root: String,
    pub resolution_root: String,
}

impl EvidenceChallenge {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "evidence_id": self.evidence_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "challenger_id": self.challenger_id,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "allegation_root": self.allegation_root,
            "counter_evidence_root": self.counter_evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "resolution_root": self.resolution_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-WATCHER-EVIDENCE-CHALLENGE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResolution {
    pub challenge_id: String,
    pub sustained: bool,
    pub resolver_id: String,
    pub resolved_at_height: u64,
    pub resolution_root: String,
    pub pq_signature_root: String,
    pub public_note_root: String,
}

impl ChallengeResolution {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "sustained": self.sustained,
            "resolver_id": self.resolver_id,
            "resolved_at_height": self.resolved_at_height,
            "resolution_root": self.resolution_root,
            "pq_signature_root": self.pq_signature_root,
            "public_note_root": self.public_note_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub evidence_id: String,
    pub challenge_id: Option<String>,
    pub batch_id: Option<String>,
    pub kind: ReceiptKind,
    pub issued_at_height: u64,
    pub actor_id: String,
    pub receipt_root: String,
    pub event_root: String,
}

impl EvidenceReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "evidence_id": self.evidence_id,
            "challenge_id": self.challenge_id,
            "batch_id": self.batch_id,
            "kind": self.kind.as_str(),
            "issued_at_height": self.issued_at_height,
            "actor_id": self.actor_id,
            "receipt_root": self.receipt_root,
            "event_root": self.event_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root("MONERO-L2-WATCHER-EVIDENCE-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityEvidenceBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub status: BatchStatus,
    pub from_l2_height: u64,
    pub to_l2_height: u64,
    pub built_at_height: u64,
    pub evidence_count: u64,
    pub accepted_count: u64,
    pub header_root: String,
    pub txset_root: String,
    pub reorg_evidence_root: String,
    pub pq_signature_root: String,
    pub selective_disclosure_root: String,
    pub receipt_root: String,
    pub evidence_root: String,
    pub finality_batch_root: String,
    pub previous_batch_root: String,
}

impl FinalityEvidenceBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "from_l2_height": self.from_l2_height,
            "to_l2_height": self.to_l2_height,
            "built_at_height": self.built_at_height,
            "evidence_count": self.evidence_count,
            "accepted_count": self.accepted_count,
            "header_root": self.header_root,
            "txset_root": self.txset_root,
            "reorg_evidence_root": self.reorg_evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "receipt_root": self.receipt_root,
            "evidence_root": self.evidence_root,
            "finality_batch_root": self.finality_batch_root,
            "previous_batch_root": self.previous_batch_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root("MONERO-L2-WATCHER-EVIDENCE-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroL2WatcherEvidenceLaneRoots {
    pub evidence_root: String,
    pub challenge_root: String,
    pub receipt_root: String,
    pub batch_root: String,
    pub header_root: String,
    pub txset_root: String,
    pub reorg_evidence_root: String,
    pub pq_signature_root: String,
    pub selective_disclosure_root: String,
}

impl MoneroL2WatcherEvidenceLaneRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_root": self.evidence_root,
            "challenge_root": self.challenge_root,
            "receipt_root": self.receipt_root,
            "batch_root": self.batch_root,
            "header_root": self.header_root,
            "txset_root": self.txset_root,
            "reorg_evidence_root": self.reorg_evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "selective_disclosure_root": self.selective_disclosure_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroL2WatcherEvidenceLaneState {
    pub config: MoneroL2WatcherEvidenceLaneConfig,
    pub counters: MoneroL2WatcherEvidenceLaneCounters,
    pub evidence: BTreeMap<String, WatcherEvidence>,
    pub challenges: BTreeMap<String, EvidenceChallenge>,
    pub receipts: BTreeMap<String, EvidenceReceipt>,
    pub batches: BTreeMap<String, FinalityEvidenceBatch>,
    pub evidence_by_height: BTreeMap<u64, BTreeSet<String>>,
    pub open_challenges_by_deadline: BTreeMap<u64, BTreeSet<String>>,
}

impl MoneroL2WatcherEvidenceLaneState {
    pub fn devnet() -> Self {
        Self {
            config: MoneroL2WatcherEvidenceLaneConfig::devnet(),
            counters: MoneroL2WatcherEvidenceLaneCounters::default(),
            evidence: BTreeMap::new(),
            challenges: BTreeMap::new(),
            receipts: BTreeMap::new(),
            batches: BTreeMap::new(),
            evidence_by_height: BTreeMap::new(),
            open_challenges_by_deadline: BTreeMap::new(),
        }
    }

    pub fn submit_evidence(
        &mut self,
        submission: EvidenceSubmission,
    ) -> MoneroL2WatcherEvidenceLaneResult<EvidenceReceipt> {
        validate_submission(&submission)?;
        if self.evidence.len() >= MONERO_L2_WATCHER_EVIDENCE_LANE_MAX_EVIDENCE {
            return Err("watcher evidence lane capacity reached".to_string());
        }

        let sequence = self.counters.next_evidence_sequence;
        self.counters.next_evidence_sequence =
            self.counters.next_evidence_sequence.saturating_add(1);
        let challenge_deadline_height = submission
            .l2_height
            .saturating_add(self.config.challenge_window_blocks.max(1));
        let evidence_root = submission.root();
        let evidence_id = evidence_id(sequence, &submission, &evidence_root);
        if self.evidence.contains_key(&evidence_id) {
            return Err(format!("duplicate evidence id: {evidence_id}"));
        }

        let mut evidence = WatcherEvidence {
            evidence_id: evidence_id.clone(),
            sequence,
            kind: submission.kind,
            status: EvidenceStatus::ChallengeOpen,
            monero_height: submission.monero_height,
            l2_height: submission.l2_height,
            observed_at_height: submission.observed_at_height,
            submitted_at_height: submission.l2_height,
            challenge_deadline_height,
            watcher_id: submission.watcher_id.clone(),
            watcher_weight: submission.watcher_weight,
            header_root: submission.header_root,
            txset_root: submission.txset_root,
            reorg_evidence_root: submission.reorg_evidence_root,
            pq_signature_root: submission.pq_signature_root,
            selective_disclosure_root: submission.selective_disclosure_root,
            finality_context_root: submission.finality_context_root,
            bridge_context_root: submission.bridge_context_root,
            evidence_root,
            previous_evidence_root: submission.previous_evidence_root,
            challenge_root: empty_root("MONERO-L2-WATCHER-EVIDENCE-CHALLENGE"),
            receipt_root: empty_root("MONERO-L2-WATCHER-EVIDENCE-RECEIPT"),
            batch_id: None,
        };

        let receipt = self.issue_receipt(
            &evidence_id,
            None,
            None,
            ReceiptKind::Submitted,
            evidence.submitted_at_height,
            &evidence.watcher_id,
            &evidence.evidence_root,
        )?;
        evidence.receipt_root = receipt.root();

        self.evidence_by_height
            .entry(evidence.l2_height)
            .or_default()
            .insert(evidence_id.clone());
        self.evidence.insert(evidence_id, evidence);
        self.counters.submitted_evidence = self.counters.submitted_evidence.saturating_add(1);
        Ok(receipt)
    }

    pub fn open_challenge(
        &mut self,
        evidence_id: &str,
        challenger_id: impl Into<String>,
        opened_at_height: u64,
        allegation_root: impl Into<String>,
        counter_evidence_root: impl Into<String>,
        pq_signature_root: impl Into<String>,
        selective_disclosure_root: impl Into<String>,
    ) -> MoneroL2WatcherEvidenceLaneResult<EvidenceReceipt> {
        let challenger_id = challenger_id.into();
        let allegation_root = allegation_root.into();
        let counter_evidence_root = counter_evidence_root.into();
        let pq_signature_root = pq_signature_root.into();
        let selective_disclosure_root = selective_disclosure_root.into();
        validate_root("allegation_root", &allegation_root)?;
        validate_root("counter_evidence_root", &counter_evidence_root)?;
        validate_root("pq_signature_root", &pq_signature_root)?;
        validate_root("selective_disclosure_root", &selective_disclosure_root)?;

        let deadline_height = {
            let evidence = self
                .evidence
                .get(evidence_id)
                .ok_or_else(|| format!("unknown evidence id: {evidence_id}"))?;
            if evidence.status.terminal() {
                return Err("terminal evidence cannot be challenged".to_string());
            }
            if opened_at_height > evidence.challenge_deadline_height {
                return Err("challenge window already closed".to_string());
            }
            evidence.challenge_deadline_height
        };

        let sequence = self.counters.next_challenge_sequence;
        self.counters.next_challenge_sequence =
            self.counters.next_challenge_sequence.saturating_add(1);
        let challenge_id = challenge_id(sequence, evidence_id, &challenger_id, &allegation_root);
        let challenge = EvidenceChallenge {
            challenge_id: challenge_id.clone(),
            evidence_id: evidence_id.to_string(),
            sequence,
            status: ChallengeStatus::Open,
            challenger_id: challenger_id.clone(),
            opened_at_height,
            deadline_height,
            allegation_root,
            counter_evidence_root,
            pq_signature_root,
            selective_disclosure_root,
            resolution_root: empty_root("MONERO-L2-WATCHER-EVIDENCE-CHALLENGE-RESOLUTION"),
        };
        let challenge_root = challenge.root();
        self.challenges.insert(challenge_id.clone(), challenge);
        self.open_challenges_by_deadline
            .entry(deadline_height)
            .or_default()
            .insert(challenge_id.clone());

        let receipt = self.issue_receipt(
            evidence_id,
            Some(&challenge_id),
            None,
            ReceiptKind::ChallengeOpened,
            opened_at_height,
            &challenger_id,
            &challenge_root,
        )?;
        if let Some(evidence) = self.evidence.get_mut(evidence_id) {
            evidence.status = EvidenceStatus::Challenged;
            evidence.challenge_root = challenge_root;
            evidence.receipt_root = receipt.root();
        }
        self.counters.challenged_evidence = self.counters.challenged_evidence.saturating_add(1);
        Ok(receipt)
    }

    pub fn resolve_challenge(
        &mut self,
        resolution: ChallengeResolution,
    ) -> MoneroL2WatcherEvidenceLaneResult<EvidenceReceipt> {
        validate_root("resolution_root", &resolution.resolution_root)?;
        validate_root("pq_signature_root", &resolution.pq_signature_root)?;
        validate_root("public_note_root", &resolution.public_note_root)?;

        let (evidence_id, challenger_id, deadline_height) = {
            let challenge = self
                .challenges
                .get(&resolution.challenge_id)
                .ok_or_else(|| format!("unknown challenge id: {}", resolution.challenge_id))?;
            if challenge.status.terminal() {
                return Err("challenge already resolved".to_string());
            }
            if resolution.resolved_at_height > challenge.deadline_height {
                return Err("challenge resolution missed deadline".to_string());
            }
            (
                challenge.evidence_id.clone(),
                challenge.challenger_id.clone(),
                challenge.deadline_height,
            )
        };

        let resolution_record = resolution.public_record();
        let resolved_root = lane_root(
            "MONERO-L2-WATCHER-EVIDENCE-CHALLENGE-RESOLUTION",
            &resolution_record,
        );
        if let Some(challenge) = self.challenges.get_mut(&resolution.challenge_id) {
            challenge.status = if resolution.sustained {
                ChallengeStatus::Sustained
            } else {
                ChallengeStatus::Rejected
            };
            challenge.resolution_root = resolved_root.clone();
            challenge.pq_signature_root = resolution.pq_signature_root.clone();
        }
        if let Some(ids) = self.open_challenges_by_deadline.get_mut(&deadline_height) {
            ids.remove(&resolution.challenge_id);
        }

        let receipt_kind = if resolution.sustained {
            ReceiptKind::Rejected
        } else {
            ReceiptKind::Accepted
        };
        let actor = if resolution.sustained {
            challenger_id
        } else {
            resolution.resolver_id.clone()
        };
        let receipt = self.issue_receipt(
            &evidence_id,
            Some(&resolution.challenge_id),
            None,
            ReceiptKind::ChallengeResolved,
            resolution.resolved_at_height,
            &actor,
            &resolved_root,
        )?;
        let terminal_receipt = self.issue_receipt(
            &evidence_id,
            Some(&resolution.challenge_id),
            None,
            receipt_kind,
            resolution.resolved_at_height,
            &actor,
            &receipt.root(),
        )?;

        if let Some(evidence) = self.evidence.get_mut(&evidence_id) {
            evidence.status = if resolution.sustained {
                self.counters.rejected_evidence = self.counters.rejected_evidence.saturating_add(1);
                EvidenceStatus::Rejected
            } else {
                self.counters.accepted_evidence = self.counters.accepted_evidence.saturating_add(1);
                EvidenceStatus::Accepted
            };
            evidence.challenge_root = resolved_root;
            evidence.receipt_root = terminal_receipt.root();
        }
        Ok(terminal_receipt)
    }

    pub fn build_evidence_batch(
        &mut self,
        from_l2_height: u64,
        to_l2_height: u64,
        built_at_height: u64,
    ) -> MoneroL2WatcherEvidenceLaneResult<FinalityEvidenceBatch> {
        if from_l2_height > to_l2_height {
            return Err("invalid batch height range".to_string());
        }
        if self.batches.len() >= MONERO_L2_WATCHER_EVIDENCE_LANE_MAX_BATCHES {
            return Err("watcher evidence batch capacity reached".to_string());
        }

        self.expire_open_windows(built_at_height)?;
        let mut selected_ids = Vec::new();
        for (_height, ids) in self.evidence_by_height.range(from_l2_height..=to_l2_height) {
            for evidence_id in ids {
                let Some(evidence) = self.evidence.get(evidence_id) else {
                    continue;
                };
                if selected_ids.len() >= self.config.max_batch_size.max(1) {
                    break;
                }
                if evidence.status.batchable()
                    && built_at_height >= evidence.challenge_deadline_height
                {
                    selected_ids.push(evidence_id.clone());
                }
            }
        }
        if selected_ids.is_empty() {
            return Err("no batchable evidence in requested range".to_string());
        }

        let sequence = self.counters.next_batch_sequence;
        self.counters.next_batch_sequence = self.counters.next_batch_sequence.saturating_add(1);
        let previous_batch_root = self
            .batches
            .values()
            .last()
            .map(FinalityEvidenceBatch::root)
            .unwrap_or_else(|| empty_root("MONERO-L2-WATCHER-EVIDENCE-BATCH"));

        let selected = selected_ids
            .iter()
            .filter_map(|id| self.evidence.get(id))
            .cloned()
            .collect::<Vec<_>>();
        let evidence_records = selected
            .iter()
            .map(WatcherEvidence::roots_record)
            .collect::<Vec<_>>();
        let header_records = selected
            .iter()
            .map(|evidence| json!({"evidence_id": evidence.evidence_id, "header_root": evidence.header_root}))
            .collect::<Vec<_>>();
        let txset_records = selected
            .iter()
            .map(|evidence| json!({"evidence_id": evidence.evidence_id, "txset_root": evidence.txset_root}))
            .collect::<Vec<_>>();
        let reorg_records = selected
            .iter()
            .map(|evidence| {
                json!({"evidence_id": evidence.evidence_id, "reorg_evidence_root": evidence.reorg_evidence_root})
            })
            .collect::<Vec<_>>();
        let pq_records = selected
            .iter()
            .map(|evidence| {
                json!({"evidence_id": evidence.evidence_id, "pq_signature_root": evidence.pq_signature_root})
            })
            .collect::<Vec<_>>();
        let disclosure_records = selected
            .iter()
            .map(|evidence| {
                json!({"evidence_id": evidence.evidence_id, "selective_disclosure_root": evidence.selective_disclosure_root})
            })
            .collect::<Vec<_>>();
        let receipt_records = selected
            .iter()
            .map(|evidence| json!({"evidence_id": evidence.evidence_id, "receipt_root": evidence.receipt_root}))
            .collect::<Vec<_>>();

        let evidence_root = merkle_root(
            "MONERO-L2-WATCHER-EVIDENCE-BATCH-EVIDENCE",
            &evidence_records,
        );
        let header_root = merkle_root("MONERO-L2-WATCHER-EVIDENCE-BATCH-HEADERS", &header_records);
        let txset_root = merkle_root("MONERO-L2-WATCHER-EVIDENCE-BATCH-TXSETS", &txset_records);
        let reorg_evidence_root =
            merkle_root("MONERO-L2-WATCHER-EVIDENCE-BATCH-REORGS", &reorg_records);
        let pq_signature_root = merkle_root("MONERO-L2-WATCHER-EVIDENCE-BATCH-PQ", &pq_records);
        let selective_disclosure_root = merkle_root(
            "MONERO-L2-WATCHER-EVIDENCE-BATCH-DISCLOSURES",
            &disclosure_records,
        );
        let receipt_root = merkle_root(
            "MONERO-L2-WATCHER-EVIDENCE-BATCH-RECEIPTS",
            &receipt_records,
        );

        let accepted_count = selected
            .iter()
            .filter(|evidence| evidence.status == EvidenceStatus::Accepted)
            .count() as u64;
        let batch_seed = json!({
            "sequence": sequence,
            "from_l2_height": from_l2_height,
            "to_l2_height": to_l2_height,
            "built_at_height": built_at_height,
            "evidence_root": evidence_root.clone(),
            "header_root": header_root.clone(),
            "txset_root": txset_root.clone(),
            "reorg_evidence_root": reorg_evidence_root.clone(),
            "pq_signature_root": pq_signature_root.clone(),
            "selective_disclosure_root": selective_disclosure_root.clone(),
            "receipt_root": receipt_root.clone(),
            "previous_batch_root": previous_batch_root.clone(),
        });
        let finality_batch_root = lane_root("MONERO-L2-WATCHER-EVIDENCE-BATCH-SEED", &batch_seed);
        let batch_id = batch_id(sequence, &finality_batch_root);
        let batch = FinalityEvidenceBatch {
            batch_id: batch_id.clone(),
            sequence,
            status: BatchStatus::Built,
            from_l2_height,
            to_l2_height,
            built_at_height,
            evidence_count: selected.len() as u64,
            accepted_count,
            header_root,
            txset_root,
            reorg_evidence_root,
            pq_signature_root,
            selective_disclosure_root,
            receipt_root,
            evidence_root,
            finality_batch_root,
            previous_batch_root,
        };

        self.batches.insert(batch_id.clone(), batch.clone());
        for evidence_id in selected_ids {
            let actor_id = self
                .evidence
                .get(&evidence_id)
                .map(|evidence| evidence.watcher_id.clone())
                .unwrap_or_default();
            let receipt = self.issue_receipt(
                &evidence_id,
                None,
                Some(&batch_id),
                ReceiptKind::Batched,
                built_at_height,
                &actor_id,
                &batch.finality_batch_root,
            )?;
            if let Some(evidence) = self.evidence.get_mut(&evidence_id) {
                evidence.status = EvidenceStatus::Batched;
                evidence.batch_id = Some(batch_id.clone());
                evidence.receipt_root = receipt.root();
            }
        }
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        Ok(batch)
    }

    pub fn roots(&self) -> MoneroL2WatcherEvidenceLaneRoots {
        let evidence_records = self
            .evidence
            .values()
            .map(WatcherEvidence::public_record)
            .collect::<Vec<_>>();
        let challenge_records = self
            .challenges
            .values()
            .map(EvidenceChallenge::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(EvidenceReceipt::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(FinalityEvidenceBatch::public_record)
            .collect::<Vec<_>>();
        let header_records = self
            .evidence
            .values()
            .map(|evidence| json!({"id": evidence.evidence_id, "root": evidence.header_root}))
            .collect::<Vec<_>>();
        let txset_records = self
            .evidence
            .values()
            .map(|evidence| json!({"id": evidence.evidence_id, "root": evidence.txset_root}))
            .collect::<Vec<_>>();
        let reorg_records = self
            .evidence
            .values()
            .map(|evidence| json!({"id": evidence.evidence_id, "root": evidence.reorg_evidence_root}))
            .collect::<Vec<_>>();
        let pq_records = self
            .evidence
            .values()
            .map(|evidence| json!({"id": evidence.evidence_id, "root": evidence.pq_signature_root}))
            .collect::<Vec<_>>();
        let disclosure_records = self
            .evidence
            .values()
            .map(|evidence| {
                json!({"id": evidence.evidence_id, "root": evidence.selective_disclosure_root})
            })
            .collect::<Vec<_>>();

        MoneroL2WatcherEvidenceLaneRoots {
            evidence_root: merkle_root(
                "MONERO-L2-WATCHER-EVIDENCE-STATE-EVIDENCE",
                &evidence_records,
            ),
            challenge_root: merkle_root(
                "MONERO-L2-WATCHER-EVIDENCE-STATE-CHALLENGE",
                &challenge_records,
            ),
            receipt_root: merkle_root("MONERO-L2-WATCHER-EVIDENCE-STATE-RECEIPT", &receipt_records),
            batch_root: merkle_root("MONERO-L2-WATCHER-EVIDENCE-STATE-BATCH", &batch_records),
            header_root: merkle_root("MONERO-L2-WATCHER-EVIDENCE-STATE-HEADER", &header_records),
            txset_root: merkle_root("MONERO-L2-WATCHER-EVIDENCE-STATE-TXSET", &txset_records),
            reorg_evidence_root: merkle_root(
                "MONERO-L2-WATCHER-EVIDENCE-STATE-REORG",
                &reorg_records,
            ),
            pq_signature_root: merkle_root("MONERO-L2-WATCHER-EVIDENCE-STATE-PQ", &pq_records),
            selective_disclosure_root: merkle_root(
                "MONERO-L2-WATCHER-EVIDENCE-STATE-DISCLOSURE",
                &disclosure_records,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_WATCHER_EVIDENCE_LANE_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "config_root": self.config.root(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "evidence_count": self.evidence.len(),
            "challenge_count": self.challenges.len(),
            "receipt_count": self.receipts.len(),
            "batch_count": self.batches.len(),
        })
    }

    pub fn state_root(&self) -> String {
        lane_root("MONERO-L2-WATCHER-EVIDENCE-STATE", &self.public_record())
    }

    fn expire_open_windows(
        &mut self,
        current_l2_height: u64,
    ) -> MoneroL2WatcherEvidenceLaneResult<()> {
        let expired_deadlines = self
            .open_challenges_by_deadline
            .range(..current_l2_height)
            .map(|(deadline, _)| *deadline)
            .collect::<Vec<_>>();
        for deadline in expired_deadlines {
            let Some(challenge_ids) = self.open_challenges_by_deadline.remove(&deadline) else {
                continue;
            };
            for challenge_id in challenge_ids {
                if let Some(challenge) = self.challenges.get_mut(&challenge_id) {
                    if challenge.status == ChallengeStatus::Open {
                        challenge.status = ChallengeStatus::Expired;
                    }
                }
            }
        }

        let evidence_ids = self.evidence.keys().cloned().collect::<Vec<_>>();
        for evidence_id in evidence_ids {
            let should_accept = self
                .evidence
                .get(&evidence_id)
                .map(|evidence| {
                    evidence.status == EvidenceStatus::ChallengeOpen
                        && current_l2_height >= evidence.challenge_deadline_height
                })
                .unwrap_or(false);
            if should_accept {
                let (actor_id, evidence_root) = self
                    .evidence
                    .get(&evidence_id)
                    .map(|evidence| (evidence.watcher_id.clone(), evidence.evidence_root.clone()))
                    .unwrap_or_default();
                let receipt = self.issue_receipt(
                    &evidence_id,
                    None,
                    None,
                    ReceiptKind::Accepted,
                    current_l2_height,
                    &actor_id,
                    &evidence_root,
                )?;
                if let Some(evidence) = self.evidence.get_mut(&evidence_id) {
                    evidence.status = EvidenceStatus::Accepted;
                    evidence.receipt_root = receipt.root();
                }
                self.counters.accepted_evidence = self.counters.accepted_evidence.saturating_add(1);
            }
        }
        Ok(())
    }

    fn issue_receipt(
        &mut self,
        evidence_id: &str,
        challenge_id: Option<&str>,
        batch_id: Option<&str>,
        kind: ReceiptKind,
        issued_at_height: u64,
        actor_id: &str,
        event_root: &str,
    ) -> MoneroL2WatcherEvidenceLaneResult<EvidenceReceipt> {
        if self.receipts.len() >= MONERO_L2_WATCHER_EVIDENCE_LANE_MAX_RECEIPTS {
            return Err("watcher evidence receipt capacity reached".to_string());
        }
        validate_root("event_root", event_root)?;
        let sequence = self.counters.next_receipt_sequence;
        self.counters.next_receipt_sequence = self.counters.next_receipt_sequence.saturating_add(1);
        let receipt_root = receipt_root(
            sequence,
            evidence_id,
            challenge_id,
            batch_id,
            kind,
            issued_at_height,
            actor_id,
            event_root,
        );
        let receipt_id = receipt_id(sequence, &receipt_root);
        let receipt = EvidenceReceipt {
            receipt_id: receipt_id.clone(),
            sequence,
            evidence_id: evidence_id.to_string(),
            challenge_id: challenge_id.map(str::to_string),
            batch_id: batch_id.map(str::to_string),
            kind,
            issued_at_height,
            actor_id: actor_id.to_string(),
            receipt_root,
            event_root: event_root.to_string(),
        };
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }
}

pub type State = MoneroL2WatcherEvidenceLaneState;

pub fn header_chain_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-WATCHER-EVIDENCE-HEADER-CHAIN", records)
}

pub fn txset_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-WATCHER-EVIDENCE-TXSET", records)
}

pub fn reorg_evidence_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-WATCHER-EVIDENCE-REORG", records)
}

pub fn watcher_pq_signature_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-WATCHER-EVIDENCE-PQ-SIGNATURE", records)
}

pub fn selective_disclosure_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-WATCHER-EVIDENCE-SELECTIVE-DISCLOSURE", records)
}

pub fn finality_context_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-WATCHER-EVIDENCE-FINALITY-CONTEXT", records)
}

pub fn bridge_context_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-WATCHER-EVIDENCE-BRIDGE-CONTEXT", records)
}

fn evidence_id(sequence: u64, submission: &EvidenceSubmission, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-WATCHER-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(submission.kind.as_str()),
            HashPart::Int(submission.monero_height as i128),
            HashPart::Int(submission.l2_height as i128),
            HashPart::Str(&submission.watcher_id),
            HashPart::Str(evidence_root),
            HashPart::Str(&submission.evidence_nonce),
        ],
        32,
    )
}

fn challenge_id(
    sequence: u64,
    evidence_id: &str,
    challenger_id: &str,
    allegation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-WATCHER-EVIDENCE-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(evidence_id),
            HashPart::Str(challenger_id),
            HashPart::Str(allegation_root),
        ],
        32,
    )
}

fn receipt_id(sequence: u64, receipt_root: &str) -> String {
    domain_hash(
        "MONERO-L2-WATCHER-EVIDENCE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(receipt_root),
        ],
        32,
    )
}

fn batch_id(sequence: u64, finality_batch_root: &str) -> String {
    domain_hash(
        "MONERO-L2-WATCHER-EVIDENCE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(finality_batch_root),
        ],
        32,
    )
}

fn receipt_root(
    sequence: u64,
    evidence_id: &str,
    challenge_id: Option<&str>,
    batch_id: Option<&str>,
    kind: ReceiptKind,
    issued_at_height: u64,
    actor_id: &str,
    event_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-WATCHER-EVIDENCE-RECEIPT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(evidence_id),
            HashPart::Str(challenge_id.unwrap_or("")),
            HashPart::Str(batch_id.unwrap_or("")),
            HashPart::Str(kind.as_str()),
            HashPart::Int(issued_at_height as i128),
            HashPart::Str(actor_id),
            HashPart::Str(event_root),
        ],
        32,
    )
}

fn lane_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn validate_submission(submission: &EvidenceSubmission) -> MoneroL2WatcherEvidenceLaneResult<()> {
    if submission.watcher_id.trim().is_empty() {
        return Err("watcher_id is required".to_string());
    }
    if submission.watcher_weight == 0 {
        return Err("watcher_weight must be nonzero".to_string());
    }
    if submission.evidence_nonce.trim().is_empty() {
        return Err("evidence_nonce is required".to_string());
    }
    validate_root("header_root", &submission.header_root)?;
    validate_root("txset_root", &submission.txset_root)?;
    validate_root("reorg_evidence_root", &submission.reorg_evidence_root)?;
    validate_root("pq_signature_root", &submission.pq_signature_root)?;
    validate_root(
        "selective_disclosure_root",
        &submission.selective_disclosure_root,
    )?;
    validate_root("finality_context_root", &submission.finality_context_root)?;
    validate_root("bridge_context_root", &submission.bridge_context_root)?;
    validate_root("previous_evidence_root", &submission.previous_evidence_root)?;
    Ok(())
}

fn validate_root(name: &str, root: &str) -> MoneroL2WatcherEvidenceLaneResult<()> {
    if root.trim().is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}
