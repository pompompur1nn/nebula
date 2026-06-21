use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;
pub type MoneroL2PqBridgeExitForceExitWave89ReleaseCaptainNoGoEvidenceArchiveFinalTranscriptRuntimeResult<
    T,
> = Result<T>;

pub const MONERO_L2_PQ_BRIDGE_EXIT_FORCE_EXIT_WAVE89_RELEASE_CAPTAIN_NO_GO_EVIDENCE_ARCHIVE_FINAL_TRANSCRIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-force-exit-wave89-release-captain-no-go-evidence-archive-final-transcript-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_FORCE_EXIT_WAVE89_RELEASE_CAPTAIN_NO_GO_EVIDENCE_ARCHIVE_FINAL_TRANSCRIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ARCHIVE_SUITE: &str = "monero-l2-pq-force-exit-release-captain-no-go-evidence-archive-v1";
pub const DEFAULT_WAVE: u64 = 89;
pub const DEFAULT_SOURCE_WAVE: u64 = 88;
pub const DEFAULT_COMMAND_CHECKLIST_WAVE: u64 = 87;
pub const DEFAULT_ARCHIVE_HEIGHT: u64 = 890_000;
pub const DEFAULT_MIN_ARCHIVED_LANES: u16 = 6;
pub const DEFAULT_MIN_ITEM_COUNT: u16 = 42;
pub const DEFAULT_MIN_CAPTAIN_RECEIPTS: u16 = 6;
pub const DEFAULT_MIN_NO_GO_WEIGHT: u64 = 100;
pub const DEFAULT_MAX_ARCHIVE_AGE_BLOCKS: u64 = 72;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveLane {
    CompileGate,
    RuntimeReplayGate,
    AuditSecurityGate,
    BridgeCustodyGate,
    WalletWatchtowerGate,
    PqReservePrivacyGate,
}

impl ArchiveLane {
    pub fn all() -> Vec<Self> {
        vec![
            Self::CompileGate,
            Self::RuntimeReplayGate,
            Self::AuditSecurityGate,
            Self::BridgeCustodyGate,
            Self::WalletWatchtowerGate,
            Self::PqReservePrivacyGate,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompileGate => "compile_gate",
            Self::RuntimeReplayGate => "runtime_replay_gate",
            Self::AuditSecurityGate => "audit_security_gate",
            Self::BridgeCustodyGate => "bridge_custody_gate",
            Self::WalletWatchtowerGate => "wallet_watchtower_gate",
            Self::PqReservePrivacyGate => "pq_reserve_privacy_gate",
        }
    }

    pub fn captain_desk(self) -> &'static str {
        match self {
            Self::CompileGate => "release-captain-compile-desk",
            Self::RuntimeReplayGate => "release-captain-runtime-replay-desk",
            Self::AuditSecurityGate => "release-captain-audit-security-desk",
            Self::BridgeCustodyGate => "release-captain-bridge-custody-desk",
            Self::WalletWatchtowerGate => "release-captain-wallet-watchtower-desk",
            Self::PqReservePrivacyGate => "release-captain-pq-reserve-privacy-desk",
        }
    }

    pub fn requires_custody_receipt(self) -> bool {
        matches!(self, Self::BridgeCustodyGate | Self::PqReservePrivacyGate)
    }

    pub fn requires_privacy_receipt(self) -> bool {
        matches!(
            self,
            Self::AuditSecurityGate | Self::WalletWatchtowerGate | Self::PqReservePrivacyGate
        )
    }

    pub fn requires_runtime_receipt(self) -> bool {
        matches!(self, Self::CompileGate | Self::RuntimeReplayGate)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveItemKind {
    Wave88ReplayRoot,
    Wave87CommandChecklistRoot,
    DeferredCargoRoot,
    DeferredRuntimeReplayRoot,
    DeferredClippyRoot,
    AuditReviewHoldRoot,
    BridgeCustodyHoldRoot,
    WalletEscapeHoldRoot,
    WatchtowerQuorumHoldRoot,
    PqEpochHoldRoot,
    ReserveCoverageHoldRoot,
    PrivacyLinkageHoldRoot,
    OperatorPagerAckRoot,
    ReleaseCaptainNoGoRoot,
}

impl ArchiveItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wave88ReplayRoot => "wave88_replay_root",
            Self::Wave87CommandChecklistRoot => "wave87_command_checklist_root",
            Self::DeferredCargoRoot => "deferred_cargo_root",
            Self::DeferredRuntimeReplayRoot => "deferred_runtime_replay_root",
            Self::DeferredClippyRoot => "deferred_clippy_root",
            Self::AuditReviewHoldRoot => "audit_review_hold_root",
            Self::BridgeCustodyHoldRoot => "bridge_custody_hold_root",
            Self::WalletEscapeHoldRoot => "wallet_escape_hold_root",
            Self::WatchtowerQuorumHoldRoot => "watchtower_quorum_hold_root",
            Self::PqEpochHoldRoot => "pq_epoch_hold_root",
            Self::ReserveCoverageHoldRoot => "reserve_coverage_hold_root",
            Self::PrivacyLinkageHoldRoot => "privacy_linkage_hold_root",
            Self::OperatorPagerAckRoot => "operator_pager_ack_root",
            Self::ReleaseCaptainNoGoRoot => "release_captain_no_go_root",
        }
    }

    pub fn required_for_lane(self, lane: ArchiveLane) -> bool {
        match self {
            Self::Wave88ReplayRoot
            | Self::Wave87CommandChecklistRoot
            | Self::OperatorPagerAckRoot
            | Self::ReleaseCaptainNoGoRoot => true,
            Self::DeferredCargoRoot | Self::DeferredClippyRoot => {
                matches!(lane, ArchiveLane::CompileGate)
            }
            Self::DeferredRuntimeReplayRoot => lane.requires_runtime_receipt(),
            Self::AuditReviewHoldRoot => matches!(lane, ArchiveLane::AuditSecurityGate),
            Self::BridgeCustodyHoldRoot => lane.requires_custody_receipt(),
            Self::WalletEscapeHoldRoot | Self::WatchtowerQuorumHoldRoot => {
                matches!(lane, ArchiveLane::WalletWatchtowerGate)
            }
            Self::PqEpochHoldRoot | Self::ReserveCoverageHoldRoot => {
                matches!(lane, ArchiveLane::PqReservePrivacyGate)
            }
            Self::PrivacyLinkageHoldRoot => lane.requires_privacy_receipt(),
        }
    }

    pub fn no_go_weight(self) -> u64 {
        match self {
            Self::Wave88ReplayRoot | Self::Wave87CommandChecklistRoot => 8,
            Self::DeferredCargoRoot
            | Self::DeferredRuntimeReplayRoot
            | Self::DeferredClippyRoot => 18,
            Self::AuditReviewHoldRoot
            | Self::BridgeCustodyHoldRoot
            | Self::WalletEscapeHoldRoot
            | Self::WatchtowerQuorumHoldRoot
            | Self::PqEpochHoldRoot
            | Self::ReserveCoverageHoldRoot
            | Self::PrivacyLinkageHoldRoot => 20,
            Self::OperatorPagerAckRoot => 4,
            Self::ReleaseCaptainNoGoRoot => 22,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveDisposition {
    Missing,
    Draft,
    Deferred,
    Hold,
    NoGoArchived,
    ReplaceAfterHeavyGate,
    Rejected,
}

impl ArchiveDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Draft => "draft",
            Self::Deferred => "deferred",
            Self::Hold => "hold",
            Self::NoGoArchived => "no_go_archived",
            Self::ReplaceAfterHeavyGate => "replace_after_heavy_gate",
            Self::Rejected => "rejected",
        }
    }

    pub fn blocks_release(self) -> bool {
        !matches!(self, Self::ReplaceAfterHeavyGate)
    }

    pub fn severity(self) -> u8 {
        match self {
            Self::Missing => 10,
            Self::Rejected => 9,
            Self::Deferred => 8,
            Self::Hold => 7,
            Self::NoGoArchived => 6,
            Self::Draft => 5,
            Self::ReplaceAfterHeavyGate => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveBlockerKind {
    MissingReplayRoot,
    MissingCommandChecklistRoot,
    MissingCaptainReceipt,
    MissingLaneArchive,
    DeferredHeavyGate,
    ArchiveTooOld,
    ItemCountTooLow,
    NoGoWeightTooLow,
    CustodyReceiptMissing,
    PrivacyReceiptMissing,
    RuntimeReceiptMissing,
    ReleaseHoldActive,
    RejectedEvidence,
    EmptyRoot,
}

impl ArchiveBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingReplayRoot => "missing_replay_root",
            Self::MissingCommandChecklistRoot => "missing_command_checklist_root",
            Self::MissingCaptainReceipt => "missing_captain_receipt",
            Self::MissingLaneArchive => "missing_lane_archive",
            Self::DeferredHeavyGate => "deferred_heavy_gate",
            Self::ArchiveTooOld => "archive_too_old",
            Self::ItemCountTooLow => "item_count_too_low",
            Self::NoGoWeightTooLow => "no_go_weight_too_low",
            Self::CustodyReceiptMissing => "custody_receipt_missing",
            Self::PrivacyReceiptMissing => "privacy_receipt_missing",
            Self::RuntimeReceiptMissing => "runtime_receipt_missing",
            Self::ReleaseHoldActive => "release_hold_active",
            Self::RejectedEvidence => "rejected_evidence",
            Self::EmptyRoot => "empty_root",
        }
    }

    pub fn severity(self) -> u8 {
        match self {
            Self::MissingReplayRoot
            | Self::MissingCommandChecklistRoot
            | Self::MissingLaneArchive
            | Self::RejectedEvidence => 10,
            Self::DeferredHeavyGate
            | Self::CustodyReceiptMissing
            | Self::PrivacyReceiptMissing
            | Self::RuntimeReceiptMissing => 9,
            Self::MissingCaptainReceipt | Self::ReleaseHoldActive | Self::ArchiveTooOld => 8,
            Self::ItemCountTooLow | Self::NoGoWeightTooLow | Self::EmptyRoot => 7,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub wave: u64,
    pub source_wave: u64,
    pub command_checklist_wave: u64,
    pub chain_id: String,
    pub protocol_version: String,
    pub archive_height: u64,
    pub max_archive_age_blocks: u64,
    pub min_archived_lanes: u16,
    pub min_item_count: u16,
    pub min_captain_receipts: u16,
    pub min_no_go_weight: u64,
    pub require_custody_receipts: bool,
    pub require_privacy_receipts: bool,
    pub require_runtime_receipts: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            wave: DEFAULT_WAVE,
            source_wave: DEFAULT_SOURCE_WAVE,
            command_checklist_wave: DEFAULT_COMMAND_CHECKLIST_WAVE,
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            archive_height: DEFAULT_ARCHIVE_HEIGHT,
            max_archive_age_blocks: DEFAULT_MAX_ARCHIVE_AGE_BLOCKS,
            min_archived_lanes: DEFAULT_MIN_ARCHIVED_LANES,
            min_item_count: DEFAULT_MIN_ITEM_COUNT,
            min_captain_receipts: DEFAULT_MIN_CAPTAIN_RECEIPTS,
            min_no_go_weight: DEFAULT_MIN_NO_GO_WEIGHT,
            require_custody_receipts: true,
            require_privacy_receipts: true,
            require_runtime_receipts: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure(self.wave >= self.source_wave, "wave must cover source wave")?;
        ensure(
            self.source_wave >= self.command_checklist_wave,
            "source wave must cover command checklist wave",
        )?;
        ensure(self.archive_height > 0, "archive height must be positive")?;
        ensure(
            self.max_archive_age_blocks > 0,
            "max archive age must be positive",
        )?;
        ensure(
            self.min_archived_lanes > 0,
            "min archived lanes must be positive",
        )?;
        ensure(self.min_item_count > 0, "min item count must be positive")?;
        ensure(
            self.min_captain_receipts > 0,
            "min captain receipts must be positive",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wave89_no_go_archive_config",
            "wave": self.wave,
            "source_wave": self.source_wave,
            "command_checklist_wave": self.command_checklist_wave,
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "archive_height": self.archive_height,
            "max_archive_age_blocks": self.max_archive_age_blocks,
            "min_archived_lanes": self.min_archived_lanes,
            "min_item_count": self.min_item_count,
            "min_captain_receipts": self.min_captain_receipts,
            "min_no_go_weight": self.min_no_go_weight,
            "require_custody_receipts": self.require_custody_receipts,
            "require_privacy_receipts": self.require_privacy_receipts,
            "require_runtime_receipts": self.require_runtime_receipts,
            "hash_suite": HASH_SUITE,
            "archive_suite": ARCHIVE_SUITE,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArchiveEvidenceItem {
    pub item_id: String,
    pub lane: ArchiveLane,
    pub kind: ArchiveItemKind,
    pub disposition: ArchiveDisposition,
    pub source_wave: u64,
    pub observed_height: u64,
    pub evidence_root: String,
    pub redacted_payload_root: String,
    pub operator_receipt_root: String,
    pub no_go_weight: u64,
    pub privacy_preserving: bool,
}

impl ArchiveEvidenceItem {
    pub fn new(
        lane: ArchiveLane,
        kind: ArchiveItemKind,
        disposition: ArchiveDisposition,
        config: &Config,
        ordinal: u64,
    ) -> Result<Self> {
        let source_wave = match kind {
            ArchiveItemKind::Wave87CommandChecklistRoot => config.command_checklist_wave,
            ArchiveItemKind::Wave88ReplayRoot => config.source_wave,
            _ => config.wave,
        };
        let observed_height = config.archive_height.saturating_sub(ordinal);
        let evidence_root = sample_root("evidence", lane.as_str(), kind.as_str(), ordinal);
        let redacted_payload_root =
            sample_root("redacted-payload", lane.as_str(), kind.as_str(), ordinal);
        let operator_receipt_root =
            sample_root("operator-receipt", lane.as_str(), kind.as_str(), ordinal);
        let item_id = stable_id(
            "archive-evidence-item",
            lane.as_str(),
            kind.as_str(),
            ordinal,
        );
        let item = Self {
            item_id,
            lane,
            kind,
            disposition,
            source_wave,
            observed_height,
            evidence_root,
            redacted_payload_root,
            operator_receipt_root,
            no_go_weight: kind.no_go_weight(),
            privacy_preserving: true,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn devnet(lane: ArchiveLane, kind: ArchiveItemKind, config: &Config, ordinal: u64) -> Self {
        match Self::new(
            lane,
            kind,
            default_disposition_for_kind(kind),
            config,
            ordinal,
        ) {
            Ok(item) => item,
            Err(reason) => build_fallback_item(lane, kind, config, ordinal, reason),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("item_id", &self.item_id)?;
        ensure_non_empty("evidence_root", &self.evidence_root)?;
        ensure_non_empty("redacted_payload_root", &self.redacted_payload_root)?;
        ensure_non_empty("operator_receipt_root", &self.operator_receipt_root)?;
        ensure(
            self.kind.required_for_lane(self.lane),
            "item kind must belong to lane",
        )?;
        ensure(
            self.no_go_weight > 0,
            "no-go weight must be positive for archive item",
        )
    }

    pub fn blocks_release(&self) -> bool {
        self.disposition.blocks_release()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wave89_no_go_archive_evidence_item",
            "item_id": self.item_id,
            "lane": self.lane.as_str(),
            "item_kind": self.kind.as_str(),
            "disposition": self.disposition.as_str(),
            "source_wave": self.source_wave,
            "observed_height": self.observed_height,
            "evidence_root": self.evidence_root,
            "redacted_payload_root": self.redacted_payload_root,
            "operator_receipt_root": self.operator_receipt_root,
            "no_go_weight": self.no_go_weight,
            "privacy_preserving": self.privacy_preserving,
            "blocks_release": self.blocks_release(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("archive-evidence-item", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneArchive {
    pub lane: ArchiveLane,
    pub captain_desk: String,
    pub archived_item_count: u16,
    pub blocking_item_count: u16,
    pub no_go_weight: u64,
    pub latest_observed_height: u64,
    pub source_replay_root: String,
    pub command_checklist_root: String,
    pub lane_item_root: String,
    pub lane_blocker_root: String,
    pub disposition: ArchiveDisposition,
    pub release_allowed: bool,
}

impl LaneArchive {
    pub fn build(
        lane: ArchiveLane,
        config: &Config,
        items: &[ArchiveEvidenceItem],
        blockers: &[ArchiveBlockerKind],
        ordinal: u64,
    ) -> Self {
        let archived_item_count = items.len() as u16;
        let blocking_item_count = items.iter().filter(|item| item.blocks_release()).count() as u16;
        let no_go_weight = items.iter().map(|item| item.no_go_weight).sum::<u64>();
        let latest_observed_height = match items.iter().map(|item| item.observed_height).max() {
            Some(height) => height,
            None => config.archive_height,
        };
        let disposition = if blockers
            .iter()
            .any(|blocker| matches!(blocker, ArchiveBlockerKind::RejectedEvidence))
        {
            ArchiveDisposition::Rejected
        } else if blocking_item_count > 0 {
            ArchiveDisposition::NoGoArchived
        } else {
            ArchiveDisposition::ReplaceAfterHeavyGate
        };
        let lane_item_root = roots_root(
            "wave89-no-go-lane-items",
            items.iter().map(ArchiveEvidenceItem::state_root),
        );
        let lane_blocker_root = blocker_list_root(lane, blockers);
        let source_replay_root = sample_root("wave88-replay", lane.as_str(), "lane", ordinal);
        let command_checklist_root =
            sample_root("wave87-command-checklist", lane.as_str(), "lane", ordinal);
        Self {
            lane,
            captain_desk: lane.captain_desk().to_string(),
            archived_item_count,
            blocking_item_count,
            no_go_weight,
            latest_observed_height,
            source_replay_root,
            command_checklist_root,
            lane_item_root,
            lane_blocker_root,
            disposition,
            release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wave89_no_go_lane_archive",
            "lane": self.lane.as_str(),
            "captain_desk": self.captain_desk,
            "archived_item_count": self.archived_item_count,
            "blocking_item_count": self.blocking_item_count,
            "no_go_weight": self.no_go_weight,
            "latest_observed_height": self.latest_observed_height,
            "source_replay_root": self.source_replay_root,
            "command_checklist_root": self.command_checklist_root,
            "lane_item_root": self.lane_item_root,
            "lane_blocker_root": self.lane_blocker_root,
            "disposition": self.disposition.as_str(),
            "release_allowed": self.release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("lane-archive", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaptainArchiveReceipt {
    pub receipt_id: String,
    pub captain_id: String,
    pub lane_scope: Option<ArchiveLane>,
    pub archive_height: u64,
    pub no_go_confirmed: bool,
    pub release_hold_root: String,
    pub pager_ack_root: String,
    pub reviewer_root: String,
    pub note: String,
}

impl CaptainArchiveReceipt {
    pub fn devnet(
        captain_id: &str,
        lane_scope: Option<ArchiveLane>,
        config: &Config,
        ordinal: u64,
    ) -> Self {
        let lane_label = match lane_scope {
            Some(lane) => lane.as_str(),
            None => "all_lanes",
        };
        let receipt_id = stable_id("captain-archive-receipt", captain_id, lane_label, ordinal);
        Self {
            receipt_id,
            captain_id: captain_id.to_string(),
            lane_scope,
            archive_height: config.archive_height.saturating_add(ordinal),
            no_go_confirmed: true,
            release_hold_root: sample_root("release-hold", captain_id, lane_label, ordinal),
            pager_ack_root: sample_root("pager-ack", captain_id, lane_label, ordinal),
            reviewer_root: sample_root("reviewer", captain_id, lane_label, ordinal),
            note:
                "release remains held until live heavy-gate receipts replace deferred archive roots"
                    .to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wave89_captain_archive_receipt",
            "receipt_id": self.receipt_id,
            "captain_id": self.captain_id,
            "lane_scope": self.lane_scope.map(ArchiveLane::as_str),
            "archive_height": self.archive_height,
            "no_go_confirmed": self.no_go_confirmed,
            "release_hold_root": self.release_hold_root,
            "pager_ack_root": self.pager_ack_root,
            "reviewer_root": self.reviewer_root,
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("captain-archive-receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArchiveSummary {
    pub archived_lane_count: u16,
    pub archived_item_count: u16,
    pub captain_receipt_count: u16,
    pub total_no_go_weight: u64,
    pub max_blocker_severity: u8,
    pub release_allowed: bool,
    pub archive_complete: bool,
    pub no_go_reason_root: String,
}

impl ArchiveSummary {
    pub fn build(
        config: &Config,
        lane_archives: &[LaneArchive],
        items: &[ArchiveEvidenceItem],
        captain_receipts: &[CaptainArchiveReceipt],
        blockers: &BTreeMap<String, Vec<ArchiveBlockerKind>>,
    ) -> Self {
        let archived_lane_count = lane_archives.len() as u16;
        let archived_item_count = items.len() as u16;
        let captain_receipt_count = captain_receipts.len() as u16;
        let total_no_go_weight = items.iter().map(|item| item.no_go_weight).sum::<u64>();
        let max_blocker_severity = match blockers
            .values()
            .flat_map(|list| list.iter().map(|blocker| blocker.severity()))
            .max()
        {
            Some(severity) => severity,
            None => 0,
        };
        let archive_complete = archived_lane_count >= config.min_archived_lanes
            && archived_item_count >= config.min_item_count
            && captain_receipt_count >= config.min_captain_receipts
            && total_no_go_weight >= config.min_no_go_weight;
        let no_go_reason_root = roots_root(
            "wave89-no-go-reason-root",
            blockers.iter().map(|(subject, list)| {
                let detail = list
                    .iter()
                    .map(|blocker| blocker.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                sample_root("no-go-reason", subject, &detail, list.len() as u64)
            }),
        );
        Self {
            archived_lane_count,
            archived_item_count,
            captain_receipt_count,
            total_no_go_weight,
            max_blocker_severity,
            release_allowed: false,
            archive_complete,
            no_go_reason_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wave89_no_go_archive_summary",
            "archived_lane_count": self.archived_lane_count,
            "archived_item_count": self.archived_item_count,
            "captain_receipt_count": self.captain_receipt_count,
            "total_no_go_weight": self.total_no_go_weight,
            "max_blocker_severity": self.max_blocker_severity,
            "release_allowed": self.release_allowed,
            "archive_complete": self.archive_complete,
            "no_go_reason_root": self.no_go_reason_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("archive-summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub archive_height: u64,
    pub lane_archives: Vec<LaneArchive>,
    pub evidence_items: Vec<ArchiveEvidenceItem>,
    pub captain_receipts: Vec<CaptainArchiveReceipt>,
    pub blockers: BTreeMap<String, Vec<ArchiveBlockerKind>>,
    pub lane_archive_root: String,
    pub evidence_item_root: String,
    pub captain_receipt_root: String,
    pub blocker_root: String,
    pub summary: ArchiveSummary,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn new(
        config: Config,
        evidence_items: Vec<ArchiveEvidenceItem>,
        captain_receipts: Vec<CaptainArchiveReceipt>,
    ) -> Result<Self> {
        config.validate()?;
        let blockers = evaluate_blockers(&config, &evidence_items, &captain_receipts);
        let lane_archives = build_lane_archives(&config, &evidence_items, &blockers);
        let lane_archive_root = roots_root(
            "wave89-no-go-lane-archive-root",
            lane_archives.iter().map(LaneArchive::state_root),
        );
        let evidence_item_root = roots_root(
            "wave89-no-go-evidence-item-root",
            evidence_items.iter().map(ArchiveEvidenceItem::state_root),
        );
        let captain_receipt_root = roots_root(
            "wave89-no-go-captain-receipt-root",
            captain_receipts
                .iter()
                .map(CaptainArchiveReceipt::state_root),
        );
        let blocker_root = blockers_root(&blockers);
        let summary = ArchiveSummary::build(
            &config,
            &lane_archives,
            &evidence_items,
            &captain_receipts,
            &blockers,
        );
        Ok(Self {
            archive_height: config.archive_height,
            config,
            lane_archives,
            evidence_items,
            captain_receipts,
            blockers,
            lane_archive_root,
            evidence_item_root,
            captain_receipt_root,
            blocker_root,
            summary,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut evidence_items = Vec::new();
        let mut ordinal = 1_u64;
        for lane in ArchiveLane::all() {
            for kind in archive_kinds_for_lane(lane) {
                evidence_items.push(ArchiveEvidenceItem::devnet(lane, kind, &config, ordinal));
                ordinal = ordinal.saturating_add(1);
            }
        }
        let mut captain_receipts = Vec::new();
        for (index, lane) in ArchiveLane::all().into_iter().enumerate() {
            captain_receipts.push(CaptainArchiveReceipt::devnet(
                lane.captain_desk(),
                Some(lane),
                &config,
                one_based(index),
            ));
        }
        captain_receipts.push(CaptainArchiveReceipt::devnet(
            "release-captain-final-archive",
            None,
            &config,
            99,
        ));
        match Self::new(config, evidence_items, captain_receipts) {
            Ok(state) => state,
            Err(reason) => build_devnet_fail_closed_fallback(reason),
        }
    }

    pub fn release_allowed(&self) -> bool {
        false
    }

    pub fn lane_count(&self) -> usize {
        self.lane_archives.len()
    }

    pub fn evidence_count(&self) -> usize {
        self.evidence_items.len()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wave89_no_go_evidence_archive_final_transcript_state",
            "config": self.config.public_record(),
            "archive_height": self.archive_height,
            "lane_archive_root": self.lane_archive_root,
            "evidence_item_root": self.evidence_item_root,
            "captain_receipt_root": self.captain_receipt_root,
            "blocker_root": self.blocker_root,
            "summary": self.summary.public_record(),
            "lane_archives": self.lane_archives.iter().map(LaneArchive::public_record).collect::<Vec<_>>(),
            "captain_receipts": self.captain_receipts.iter().map(CaptainArchiveReceipt::public_record).collect::<Vec<_>>(),
            "release_allowed": self.release_allowed(),
            "heavy_gates_deferred": true,
            "production_readiness_claim_allowed": false,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
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

fn archive_kinds_for_lane(lane: ArchiveLane) -> Vec<ArchiveItemKind> {
    let kinds = vec![
        ArchiveItemKind::Wave88ReplayRoot,
        ArchiveItemKind::Wave87CommandChecklistRoot,
        ArchiveItemKind::OperatorPagerAckRoot,
        ArchiveItemKind::ReleaseCaptainNoGoRoot,
        ArchiveItemKind::DeferredCargoRoot,
        ArchiveItemKind::DeferredRuntimeReplayRoot,
        ArchiveItemKind::DeferredClippyRoot,
        ArchiveItemKind::AuditReviewHoldRoot,
        ArchiveItemKind::BridgeCustodyHoldRoot,
        ArchiveItemKind::WalletEscapeHoldRoot,
        ArchiveItemKind::WatchtowerQuorumHoldRoot,
        ArchiveItemKind::PqEpochHoldRoot,
        ArchiveItemKind::ReserveCoverageHoldRoot,
        ArchiveItemKind::PrivacyLinkageHoldRoot,
    ];
    kinds
        .into_iter()
        .filter(|kind| kind.required_for_lane(lane))
        .collect()
}

fn default_disposition_for_kind(kind: ArchiveItemKind) -> ArchiveDisposition {
    match kind {
        ArchiveItemKind::Wave88ReplayRoot
        | ArchiveItemKind::Wave87CommandChecklistRoot
        | ArchiveItemKind::OperatorPagerAckRoot => ArchiveDisposition::NoGoArchived,
        ArchiveItemKind::ReleaseCaptainNoGoRoot => ArchiveDisposition::Hold,
        ArchiveItemKind::DeferredCargoRoot
        | ArchiveItemKind::DeferredRuntimeReplayRoot
        | ArchiveItemKind::DeferredClippyRoot => ArchiveDisposition::Deferred,
        ArchiveItemKind::AuditReviewHoldRoot
        | ArchiveItemKind::BridgeCustodyHoldRoot
        | ArchiveItemKind::WalletEscapeHoldRoot
        | ArchiveItemKind::WatchtowerQuorumHoldRoot
        | ArchiveItemKind::PqEpochHoldRoot
        | ArchiveItemKind::ReserveCoverageHoldRoot
        | ArchiveItemKind::PrivacyLinkageHoldRoot => ArchiveDisposition::Hold,
    }
}

fn evaluate_blockers(
    config: &Config,
    items: &[ArchiveEvidenceItem],
    captain_receipts: &[CaptainArchiveReceipt],
) -> BTreeMap<String, Vec<ArchiveBlockerKind>> {
    let mut blockers: BTreeMap<String, Vec<ArchiveBlockerKind>> = BTreeMap::new();
    let archived_lanes = items.iter().map(|item| item.lane).collect::<BTreeSet<_>>();
    if archived_lanes.len() < config.min_archived_lanes as usize {
        blockers
            .entry("lane_archive".to_string())
            .or_default()
            .push(ArchiveBlockerKind::MissingLaneArchive);
    }
    if items.len() < config.min_item_count as usize {
        blockers
            .entry("archive_items".to_string())
            .or_default()
            .push(ArchiveBlockerKind::ItemCountTooLow);
    }
    if captain_receipts.len() < config.min_captain_receipts as usize {
        blockers
            .entry("captain_receipts".to_string())
            .or_default()
            .push(ArchiveBlockerKind::MissingCaptainReceipt);
    }
    let total_no_go_weight = items.iter().map(|item| item.no_go_weight).sum::<u64>();
    if total_no_go_weight < config.min_no_go_weight {
        blockers
            .entry("no_go_weight".to_string())
            .or_default()
            .push(ArchiveBlockerKind::NoGoWeightTooLow);
    }
    for lane in ArchiveLane::all() {
        let lane_items = items
            .iter()
            .filter(|item| item.lane == lane)
            .collect::<Vec<_>>();
        if lane_items.is_empty() {
            blockers
                .entry(lane.as_str().to_string())
                .or_default()
                .push(ArchiveBlockerKind::MissingLaneArchive);
        }
        if !lane_items
            .iter()
            .any(|item| item.kind == ArchiveItemKind::Wave88ReplayRoot)
        {
            blockers
                .entry(lane.as_str().to_string())
                .or_default()
                .push(ArchiveBlockerKind::MissingReplayRoot);
        }
        if !lane_items
            .iter()
            .any(|item| item.kind == ArchiveItemKind::Wave87CommandChecklistRoot)
        {
            blockers
                .entry(lane.as_str().to_string())
                .or_default()
                .push(ArchiveBlockerKind::MissingCommandChecklistRoot);
        }
        if config.require_custody_receipts
            && lane.requires_custody_receipt()
            && !lane_items
                .iter()
                .any(|item| item.kind == ArchiveItemKind::BridgeCustodyHoldRoot)
        {
            blockers
                .entry(lane.as_str().to_string())
                .or_default()
                .push(ArchiveBlockerKind::CustodyReceiptMissing);
        }
        if config.require_privacy_receipts
            && lane.requires_privacy_receipt()
            && !lane_items
                .iter()
                .any(|item| item.kind == ArchiveItemKind::PrivacyLinkageHoldRoot)
        {
            blockers
                .entry(lane.as_str().to_string())
                .or_default()
                .push(ArchiveBlockerKind::PrivacyReceiptMissing);
        }
        if config.require_runtime_receipts
            && lane.requires_runtime_receipt()
            && !lane_items
                .iter()
                .any(|item| item.kind == ArchiveItemKind::DeferredRuntimeReplayRoot)
        {
            blockers
                .entry(lane.as_str().to_string())
                .or_default()
                .push(ArchiveBlockerKind::RuntimeReceiptMissing);
        }
    }
    for item in items {
        if item.evidence_root.trim().is_empty()
            || item.redacted_payload_root.trim().is_empty()
            || item.operator_receipt_root.trim().is_empty()
        {
            blockers
                .entry(item.item_id.clone())
                .or_default()
                .push(ArchiveBlockerKind::EmptyRoot);
        }
        if item.disposition == ArchiveDisposition::Deferred {
            blockers
                .entry(item.lane.as_str().to_string())
                .or_default()
                .push(ArchiveBlockerKind::DeferredHeavyGate);
        }
        if item.disposition == ArchiveDisposition::Rejected {
            blockers
                .entry(item.lane.as_str().to_string())
                .or_default()
                .push(ArchiveBlockerKind::RejectedEvidence);
        }
        if config.archive_height.saturating_sub(item.observed_height)
            > config.max_archive_age_blocks
        {
            blockers
                .entry(item.item_id.clone())
                .or_default()
                .push(ArchiveBlockerKind::ArchiveTooOld);
        }
        if item.blocks_release() {
            blockers
                .entry(item.lane.as_str().to_string())
                .or_default()
                .push(ArchiveBlockerKind::ReleaseHoldActive);
        }
    }
    for receipt in captain_receipts {
        if receipt.release_hold_root.trim().is_empty()
            || receipt.pager_ack_root.trim().is_empty()
            || receipt.reviewer_root.trim().is_empty()
        {
            blockers
                .entry(receipt.receipt_id.clone())
                .or_default()
                .push(ArchiveBlockerKind::EmptyRoot);
        }
        if !receipt.no_go_confirmed {
            blockers
                .entry(receipt.receipt_id.clone())
                .or_default()
                .push(ArchiveBlockerKind::MissingCaptainReceipt);
        }
    }
    blockers
}

fn build_lane_archives(
    config: &Config,
    evidence_items: &[ArchiveEvidenceItem],
    blockers: &BTreeMap<String, Vec<ArchiveBlockerKind>>,
) -> Vec<LaneArchive> {
    ArchiveLane::all()
        .into_iter()
        .enumerate()
        .map(|(index, lane)| {
            let lane_items = evidence_items
                .iter()
                .filter(|item| item.lane == lane)
                .cloned()
                .collect::<Vec<_>>();
            let lane_blockers = match blockers.get(lane.as_str()) {
                Some(values) => values.clone(),
                None => Vec::new(),
            };
            LaneArchive::build(lane, config, &lane_items, &lane_blockers, one_based(index))
        })
        .collect()
}

fn build_devnet_fail_closed_fallback(reason: String) -> State {
    let config = Config::devnet();
    let item = build_fallback_item(
        ArchiveLane::CompileGate,
        ArchiveItemKind::DeferredCargoRoot,
        &config,
        1,
        reason,
    );
    let captain_receipt = CaptainArchiveReceipt::devnet(
        "release-captain-fallback",
        Some(ArchiveLane::CompileGate),
        &config,
        1,
    );
    let mut blockers = evaluate_blockers(&config, &[item.clone()], &[captain_receipt.clone()]);
    blockers
        .entry("fallback".to_string())
        .or_default()
        .push(ArchiveBlockerKind::DeferredHeavyGate);
    let lane_archives = build_lane_archives(&config, &[item.clone()], &blockers);
    let lane_archive_root = roots_root(
        "wave89-no-go-fallback-lanes",
        lane_archives.iter().map(LaneArchive::state_root),
    );
    let evidence_item_root = roots_root(
        "wave89-no-go-fallback-items",
        [item.state_root()].into_iter(),
    );
    let captain_receipt_root = roots_root(
        "wave89-no-go-fallback-captains",
        [captain_receipt.state_root()].into_iter(),
    );
    let blocker_root = blockers_root(&blockers);
    let summary = ArchiveSummary::build(
        &config,
        &lane_archives,
        &[item.clone()],
        &[captain_receipt.clone()],
        &blockers,
    );
    State {
        archive_height: config.archive_height,
        config,
        lane_archives,
        evidence_items: vec![item],
        captain_receipts: vec![captain_receipt],
        blockers,
        lane_archive_root,
        evidence_item_root,
        captain_receipt_root,
        blocker_root,
        summary,
    }
}

fn build_fallback_item(
    lane: ArchiveLane,
    kind: ArchiveItemKind,
    config: &Config,
    ordinal: u64,
    reason: String,
) -> ArchiveEvidenceItem {
    ArchiveEvidenceItem {
        item_id: stable_id(
            "fallback-archive-evidence-item",
            lane.as_str(),
            kind.as_str(),
            ordinal,
        ),
        lane,
        kind,
        disposition: ArchiveDisposition::Deferred,
        source_wave: config.wave,
        observed_height: config.archive_height,
        evidence_root: sample_root("fallback-evidence", lane.as_str(), &reason, ordinal),
        redacted_payload_root: sample_root("fallback-redacted", lane.as_str(), &reason, ordinal),
        operator_receipt_root: sample_root("fallback-operator", lane.as_str(), &reason, ordinal),
        no_go_weight: kind.no_go_weight(),
        privacy_preserving: true,
    }
}

fn blockers_root(blockers: &BTreeMap<String, Vec<ArchiveBlockerKind>>) -> String {
    let leaves = blockers
        .iter()
        .map(|(subject, blocker_list)| {
            let max_severity = match blocker_list.iter().map(|blocker| blocker.severity()).max() {
                Some(severity) => severity,
                None => 0,
            };
            json!({
                "subject": subject,
                "blockers": blocker_list.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
                "max_severity": max_severity,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("wave89-no-go-blockers", &leaves)
}

fn blocker_list_root(lane: ArchiveLane, blockers: &[ArchiveBlockerKind]) -> String {
    let leaves = blockers
        .iter()
        .map(|blocker| {
            json!({
                "lane": lane.as_str(),
                "blocker": blocker.as_str(),
                "severity": blocker.severity(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("wave89-no-go-lane-blockers", &leaves)
}

fn roots_root<I>(label: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = roots.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WAVE89-NO-GO-ARCHIVE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn stable_id(kind: &str, lane: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WAVE89-NO-GO-ARCHIVE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(lane),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn sample_root(kind: &str, lane: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-WAVE89-NO-GO-ARCHIVE-SAMPLE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(lane),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn one_based(index: usize) -> u64 {
    index as u64 + 1
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_non_empty(label: &str, value: &str) -> Result<()> {
    ensure(
        !value.trim().is_empty(),
        &format!("{label} must be non-empty"),
    )
}
