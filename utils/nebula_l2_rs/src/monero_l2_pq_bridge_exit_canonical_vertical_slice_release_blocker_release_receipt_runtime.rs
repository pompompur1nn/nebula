use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerReleaseReceiptRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_RELEASE_RECEIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-release-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_RELEASE_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_RECEIPT_BLOCKER_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-release-blocker-release-receipt-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_RELEASE_RECEIPT_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-release-receipt-devnet-v1";
pub const REQUIRED_RELEASE_RECEIPT_LANES: usize = 8;
pub const DEFAULT_MIN_WALLET_CONFIRMATIONS: u64 = 12;
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS: u16 = 10_000;
pub const DEFAULT_MIN_LIVE_FEED_QUORUM: u16 = 5;
pub const DEFAULT_MAX_PRIVACY_LEAKAGE_UNITS: u16 = 2;
pub const DEFAULT_REORG_WATCH_CLOSE_HEIGHT: u64 = 10_120;
pub const DEFAULT_CHALLENGE_WINDOW_CLOSE_HEIGHT: u64 = 10_160;
pub const DEFAULT_DISPUTE_WINDOW_CLOSE_HEIGHT: u64 = 10_180;
pub const DEFAULT_OBSERVED_HEIGHT: u64 = 10_100;
pub const DEFAULT_FRESHNESS_LIMIT_BLOCKS: u64 = 30;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReceiptLane {
    WalletReceipt,
    MoneroBroadcastReceipt,
    PqSignatureReceipt,
    LiquiditySettlement,
    ReorgWatch,
    ChallengeDisputeWindows,
    LiveFeedObservation,
    PrivacyBounds,
}

impl ReleaseReceiptLane {
    pub fn all() -> [Self; REQUIRED_RELEASE_RECEIPT_LANES] {
        [
            Self::WalletReceipt,
            Self::MoneroBroadcastReceipt,
            Self::PqSignatureReceipt,
            Self::LiquiditySettlement,
            Self::ReorgWatch,
            Self::ChallengeDisputeWindows,
            Self::LiveFeedObservation,
            Self::PrivacyBounds,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletReceipt => "wallet_receipt",
            Self::MoneroBroadcastReceipt => "monero_broadcast_receipt",
            Self::PqSignatureReceipt => "pq_signature_receipt",
            Self::LiquiditySettlement => "liquidity_settlement",
            Self::ReorgWatch => "reorg_watch",
            Self::ChallengeDisputeWindows => "challenge_dispute_windows",
            Self::LiveFeedObservation => "live_feed_observation",
            Self::PrivacyBounds => "privacy_bounds",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReceiptStatus {
    Clear,
    Missing,
    RootMismatch,
    ConfirmationShortfall,
    SignatureInvalid,
    LiquidityShortfall,
    WatchWindowOpen,
    ChallengeWindowOpen,
    DisputeWindowOpen,
    QuorumShortfall,
    PrivacyLeakageExceeded,
    Stale,
    HoldOpen,
}

impl ReleaseReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Missing => "missing",
            Self::RootMismatch => "root_mismatch",
            Self::ConfirmationShortfall => "confirmation_shortfall",
            Self::SignatureInvalid => "signature_invalid",
            Self::LiquidityShortfall => "liquidity_shortfall",
            Self::WatchWindowOpen => "watch_window_open",
            Self::ChallengeWindowOpen => "challenge_window_open",
            Self::DisputeWindowOpen => "dispute_window_open",
            Self::QuorumShortfall => "quorum_shortfall",
            Self::PrivacyLeakageExceeded => "privacy_leakage_exceeded",
            Self::Stale => "stale",
            Self::HoldOpen => "hold_open",
        }
    }

    pub fn blocks_release(self) -> bool {
        self != Self::Clear
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
pub enum EvidenceKind {
    WalletReceipt,
    MoneroBroadcastReceipt,
    PqSignatureReceipt,
    LiquiditySettlement,
    ReorgWatch,
    ChallengeWindow,
    DisputeWindow,
    LiveFeedObservation,
    PrivacyBounds,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletReceipt => "wallet_receipt",
            Self::MoneroBroadcastReceipt => "monero_broadcast_receipt",
            Self::PqSignatureReceipt => "pq_signature_receipt",
            Self::LiquiditySettlement => "liquidity_settlement",
            Self::ReorgWatch => "reorg_watch",
            Self::ChallengeWindow => "challenge_window",
            Self::DisputeWindow => "dispute_window",
            Self::LiveFeedObservation => "live_feed_observation",
            Self::PrivacyBounds => "privacy_bounds",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReceiptDecision {
    Acceptable,
    Blocked,
}

impl ReleaseReceiptDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Acceptable => "acceptable",
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
    pub blocker_suite: String,
    pub vertical_slice_id: String,
    pub release_receipt_id: String,
    pub required_lane_count: usize,
    pub min_wallet_confirmations: u64,
    pub min_monero_confirmations: u64,
    pub min_pq_security_bits: u16,
    pub min_liquidity_coverage_bps: u16,
    pub min_live_feed_quorum: u16,
    pub max_privacy_leakage_units: u16,
    pub reorg_watch_close_height: u64,
    pub challenge_window_close_height: u64,
    pub dispute_window_close_height: u64,
    pub observed_height: u64,
    pub freshness_limit_blocks: u64,
    pub require_wallet_root_match: bool,
    pub require_broadcast_root_match: bool,
    pub require_signature_transcript_match: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            blocker_suite: RELEASE_RECEIPT_BLOCKER_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            release_receipt_id: DEFAULT_RELEASE_RECEIPT_ID.to_string(),
            required_lane_count: REQUIRED_RELEASE_RECEIPT_LANES,
            min_wallet_confirmations: DEFAULT_MIN_WALLET_CONFIRMATIONS,
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_liquidity_coverage_bps: DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS,
            min_live_feed_quorum: DEFAULT_MIN_LIVE_FEED_QUORUM,
            max_privacy_leakage_units: DEFAULT_MAX_PRIVACY_LEAKAGE_UNITS,
            reorg_watch_close_height: DEFAULT_REORG_WATCH_CLOSE_HEIGHT,
            challenge_window_close_height: DEFAULT_CHALLENGE_WINDOW_CLOSE_HEIGHT,
            dispute_window_close_height: DEFAULT_DISPUTE_WINDOW_CLOSE_HEIGHT,
            observed_height: DEFAULT_OBSERVED_HEIGHT,
            freshness_limit_blocks: DEFAULT_FRESHNESS_LIMIT_BLOCKS,
            require_wallet_root_match: true,
            require_broadcast_root_match: true,
            require_signature_transcript_match: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "blocker_suite": self.blocker_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "release_receipt_id": self.release_receipt_id,
            "required_lane_count": self.required_lane_count,
            "min_wallet_confirmations": self.min_wallet_confirmations,
            "min_monero_confirmations": self.min_monero_confirmations,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_liquidity_coverage_bps": self.min_liquidity_coverage_bps,
            "min_live_feed_quorum": self.min_live_feed_quorum,
            "max_privacy_leakage_units": self.max_privacy_leakage_units,
            "reorg_watch_close_height": self.reorg_watch_close_height,
            "challenge_window_close_height": self.challenge_window_close_height,
            "dispute_window_close_height": self.dispute_window_close_height,
            "observed_height": self.observed_height,
            "freshness_limit_blocks": self.freshness_limit_blocks,
            "require_wallet_root_match": self.require_wallet_root_match,
            "require_broadcast_root_match": self.require_broadcast_root_match,
            "require_signature_transcript_match": self.require_signature_transcript_match,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseReceiptEvidence {
    pub evidence_id: String,
    pub lane: ReleaseReceiptLane,
    pub kind: EvidenceKind,
    pub expected_root: String,
    pub observed_root: String,
    pub root_matches: bool,
    pub confirmations: u64,
    pub required_confirmations: u64,
    pub observed_height: u64,
    pub close_height: u64,
    pub measured_bps: u16,
    pub required_bps: u16,
    pub quorum_count: u16,
    pub required_quorum: u16,
    pub security_bits: u16,
    pub required_security_bits: u16,
    pub leakage_units: u16,
    pub max_leakage_units: u16,
    pub finality_open: bool,
    pub signature_valid: bool,
    pub freshness_age_blocks: u64,
    pub freshness_limit_blocks: u64,
    pub evidence_root: String,
}

impl ReleaseReceiptEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: ReleaseReceiptLane,
        kind: EvidenceKind,
        expected_root: impl Into<String>,
        observed_root: impl Into<String>,
        confirmations: u64,
        required_confirmations: u64,
        observed_height: u64,
        close_height: u64,
        measured_bps: u16,
        required_bps: u16,
        quorum_count: u16,
        required_quorum: u16,
        security_bits: u16,
        required_security_bits: u16,
        leakage_units: u16,
        max_leakage_units: u16,
        finality_open: bool,
        signature_valid: bool,
        freshness_age_blocks: u64,
        freshness_limit_blocks: u64,
    ) -> Self {
        let expected_root = expected_root.into();
        let observed_root = observed_root.into();
        let root_matches = expected_root == observed_root;
        let draft = json!({
            "lane": lane.as_str(),
            "kind": kind.as_str(),
            "expected_root": expected_root,
            "observed_root": observed_root,
            "root_matches": root_matches,
            "confirmations": confirmations,
            "required_confirmations": required_confirmations,
            "observed_height": observed_height,
            "close_height": close_height,
            "measured_bps": measured_bps,
            "required_bps": required_bps,
            "quorum_count": quorum_count,
            "required_quorum": required_quorum,
            "security_bits": security_bits,
            "required_security_bits": required_security_bits,
            "leakage_units": leakage_units,
            "max_leakage_units": max_leakage_units,
            "finality_open": finality_open,
            "signature_valid": signature_valid,
            "freshness_age_blocks": freshness_age_blocks,
            "freshness_limit_blocks": freshness_limit_blocks,
        });
        let evidence_root = record_root("release_receipt_evidence", &draft);
        let evidence_id = id_root("release_receipt_evidence_id", lane.as_str(), &evidence_root);
        Self {
            evidence_id,
            lane,
            kind,
            expected_root,
            observed_root,
            root_matches,
            confirmations,
            required_confirmations,
            observed_height,
            close_height,
            measured_bps,
            required_bps,
            quorum_count,
            required_quorum,
            security_bits,
            required_security_bits,
            leakage_units,
            max_leakage_units,
            finality_open,
            signature_valid,
            freshness_age_blocks,
            freshness_limit_blocks,
            evidence_root,
        }
    }

    pub fn wallet(
        expected_root: impl Into<String>,
        observed_root: impl Into<String>,
        confirmations: u64,
        config: &Config,
    ) -> Self {
        Self::new(
            ReleaseReceiptLane::WalletReceipt,
            EvidenceKind::WalletReceipt,
            expected_root,
            observed_root,
            confirmations,
            config.min_wallet_confirmations,
            config.observed_height,
            config.observed_height,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            false,
            true,
            0,
            config.freshness_limit_blocks,
        )
    }

    pub fn monero_broadcast(
        expected_root: impl Into<String>,
        observed_root: impl Into<String>,
        confirmations: u64,
        age_blocks: u64,
        config: &Config,
    ) -> Self {
        Self::new(
            ReleaseReceiptLane::MoneroBroadcastReceipt,
            EvidenceKind::MoneroBroadcastReceipt,
            expected_root,
            observed_root,
            confirmations,
            config.min_monero_confirmations,
            config.observed_height,
            config.observed_height,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            false,
            true,
            age_blocks,
            config.freshness_limit_blocks,
        )
    }

    pub fn pq_signature(
        expected_root: impl Into<String>,
        observed_root: impl Into<String>,
        security_bits: u16,
        signature_valid: bool,
        age_blocks: u64,
        config: &Config,
    ) -> Self {
        Self::new(
            ReleaseReceiptLane::PqSignatureReceipt,
            EvidenceKind::PqSignatureReceipt,
            expected_root,
            observed_root,
            0,
            0,
            config.observed_height,
            config.observed_height,
            0,
            0,
            0,
            0,
            security_bits,
            config.min_pq_security_bits,
            0,
            0,
            false,
            signature_valid,
            age_blocks,
            config.freshness_limit_blocks,
        )
    }

    pub fn liquidity(
        settlement_root: impl Into<String>,
        measured_bps: u16,
        config: &Config,
    ) -> Self {
        let root = settlement_root.into();
        Self::new(
            ReleaseReceiptLane::LiquiditySettlement,
            EvidenceKind::LiquiditySettlement,
            root.clone(),
            root,
            0,
            0,
            config.observed_height,
            config.observed_height,
            measured_bps,
            config.min_liquidity_coverage_bps,
            0,
            0,
            0,
            0,
            0,
            0,
            false,
            true,
            0,
            config.freshness_limit_blocks,
        )
    }

    pub fn reorg_watch(watch_root: impl Into<String>, close_height: u64, config: &Config) -> Self {
        let root = watch_root.into();
        Self::new(
            ReleaseReceiptLane::ReorgWatch,
            EvidenceKind::ReorgWatch,
            root.clone(),
            root,
            0,
            0,
            config.observed_height,
            close_height,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            config.observed_height < close_height,
            true,
            0,
            config.freshness_limit_blocks,
        )
    }

    pub fn challenge_dispute(
        window_root: impl Into<String>,
        challenge_close_height: u64,
        dispute_close_height: u64,
        config: &Config,
    ) -> Self {
        let root = window_root.into();
        let close_height = challenge_close_height.max(dispute_close_height);
        Self::new(
            ReleaseReceiptLane::ChallengeDisputeWindows,
            EvidenceKind::ChallengeWindow,
            root.clone(),
            root,
            0,
            0,
            config.observed_height,
            close_height,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            config.observed_height < close_height,
            true,
            0,
            config.freshness_limit_blocks,
        )
    }

    pub fn live_feed(
        feed_root: impl Into<String>,
        quorum_count: u16,
        age_blocks: u64,
        config: &Config,
    ) -> Self {
        let root = feed_root.into();
        Self::new(
            ReleaseReceiptLane::LiveFeedObservation,
            EvidenceKind::LiveFeedObservation,
            root.clone(),
            root,
            0,
            0,
            config.observed_height,
            config.observed_height,
            0,
            0,
            quorum_count,
            config.min_live_feed_quorum,
            0,
            0,
            0,
            0,
            false,
            true,
            age_blocks,
            config.freshness_limit_blocks,
        )
    }

    pub fn privacy(privacy_root: impl Into<String>, leakage_units: u16, config: &Config) -> Self {
        let root = privacy_root.into();
        Self::new(
            ReleaseReceiptLane::PrivacyBounds,
            EvidenceKind::PrivacyBounds,
            root.clone(),
            root,
            0,
            0,
            config.observed_height,
            config.observed_height,
            0,
            0,
            0,
            0,
            0,
            0,
            leakage_units,
            config.max_privacy_leakage_units,
            false,
            true,
            0,
            config.freshness_limit_blocks,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "lane": self.lane.as_str(),
            "kind": self.kind.as_str(),
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "root_matches": self.root_matches,
            "confirmations": self.confirmations,
            "required_confirmations": self.required_confirmations,
            "observed_height": self.observed_height,
            "close_height": self.close_height,
            "measured_bps": self.measured_bps,
            "required_bps": self.required_bps,
            "quorum_count": self.quorum_count,
            "required_quorum": self.required_quorum,
            "security_bits": self.security_bits,
            "required_security_bits": self.required_security_bits,
            "leakage_units": self.leakage_units,
            "max_leakage_units": self.max_leakage_units,
            "finality_open": self.finality_open,
            "signature_valid": self.signature_valid,
            "freshness_age_blocks": self.freshness_age_blocks,
            "freshness_limit_blocks": self.freshness_limit_blocks,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_receipt_evidence_state", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseReceiptBlocker {
    pub blocker_id: String,
    pub lane: ReleaseReceiptLane,
    pub status: ReleaseReceiptStatus,
    pub severity: BlockerSeverity,
    pub evidence_kind: EvidenceKind,
    pub observed_root: String,
    pub expected_root: String,
    pub release_blocking: bool,
    pub required_clearance: String,
    pub evidence_root: String,
    pub blocker_root: String,
}

impl ReleaseReceiptBlocker {
    pub fn from_evidence(evidence: &ReleaseReceiptEvidence, config: &Config) -> Self {
        let status = derive_status(evidence, config);
        let severity = derive_severity(evidence.lane, status);
        let release_blocking = status.blocks_release() || !config.production_release_allowed;
        let required_clearance = clearance_for(evidence.lane, status);
        let draft = json!({
            "lane": evidence.lane.as_str(),
            "status": status.as_str(),
            "severity": severity.as_str(),
            "evidence_kind": evidence.kind.as_str(),
            "observed_root": evidence.observed_root,
            "expected_root": evidence.expected_root,
            "release_blocking": release_blocking,
            "required_clearance": required_clearance,
            "evidence_root": evidence.evidence_root,
        });
        let blocker_root = record_root("release_receipt_blocker", &draft);
        let blocker_id = id_root(
            "release_receipt_blocker_id",
            evidence.lane.as_str(),
            &blocker_root,
        );
        Self {
            blocker_id,
            lane: evidence.lane,
            status,
            severity,
            evidence_kind: evidence.kind,
            observed_root: evidence.observed_root.clone(),
            expected_root: evidence.expected_root.clone(),
            release_blocking,
            required_clearance,
            evidence_root: evidence.evidence_root.clone(),
            blocker_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "evidence_kind": self.evidence_kind.as_str(),
            "observed_root": self.observed_root,
            "expected_root": self.expected_root,
            "release_blocking": self.release_blocking,
            "required_clearance": self.required_clearance,
            "evidence_root": self.evidence_root,
            "blocker_root": self.blocker_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseReceiptReport {
    pub report_id: String,
    pub decision: ReleaseReceiptDecision,
    pub release_receipt_id: String,
    pub blocker_count: usize,
    pub blocking_count: usize,
    pub highest_severity: BlockerSeverity,
    pub total_severity_score: u64,
    pub lane_root: String,
    pub evidence_root: String,
    pub blocker_root: String,
    pub summary_root: String,
    pub config_root: String,
    pub report_root: String,
}

impl ReleaseReceiptReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "decision": self.decision.as_str(),
            "release_receipt_id": self.release_receipt_id,
            "blocker_count": self.blocker_count,
            "blocking_count": self.blocking_count,
            "highest_severity": self.highest_severity.as_str(),
            "total_severity_score": self.total_severity_score,
            "lane_root": self.lane_root,
            "evidence_root": self.evidence_root,
            "blocker_root": self.blocker_root,
            "summary_root": self.summary_root,
            "config_root": self.config_root,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub evidence: BTreeMap<ReleaseReceiptLane, ReleaseReceiptEvidence>,
    pub blockers: BTreeMap<ReleaseReceiptLane, ReleaseReceiptBlocker>,
    pub report: ReleaseReceiptReport,
}

impl State {
    pub fn evaluate(
        config: Config,
        evidence_items: Vec<ReleaseReceiptEvidence>,
    ) -> MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerReleaseReceiptRuntimeResult<Self>
    {
        let mut evidence = BTreeMap::new();
        for item in evidence_items {
            if evidence.insert(item.lane, item).is_some() {
                return Err("duplicate release receipt blocker lane".to_string());
            }
        }
        for lane in ReleaseReceiptLane::all() {
            if !evidence.contains_key(&lane) {
                return Err(format!(
                    "missing release receipt blocker lane: {}",
                    lane.as_str()
                ));
            }
        }

        let blockers = evidence
            .iter()
            .map(|(lane, item)| (*lane, ReleaseReceiptBlocker::from_evidence(item, &config)))
            .collect::<BTreeMap<_, _>>();
        let report = build_report(&config, &evidence, &blockers);
        Ok(Self {
            config,
            evidence,
            blockers,
            report,
        })
    }

    pub fn devnet_blocked_fixture() -> Self {
        let config = Config::devnet();
        let evidence = vec![
            ReleaseReceiptEvidence::wallet(
                deterministic_root("wallet_expected", "release-receipt"),
                deterministic_root("wallet_observed", "release-receipt"),
                7,
                &config,
            ),
            ReleaseReceiptEvidence::monero_broadcast(
                deterministic_root("monero_expected", "release-receipt"),
                deterministic_root("monero_expected", "release-receipt"),
                11,
                9,
                &config,
            ),
            ReleaseReceiptEvidence::pq_signature(
                deterministic_root("pq_signature_expected", "release-receipt"),
                deterministic_root("pq_signature_expected", "release-receipt"),
                192,
                false,
                3,
                &config,
            ),
            ReleaseReceiptEvidence::liquidity(
                deterministic_root("liquidity_settlement", "release-receipt"),
                9_875,
                &config,
            ),
            ReleaseReceiptEvidence::reorg_watch(
                deterministic_root("reorg_watch", "release-receipt"),
                config.reorg_watch_close_height,
                &config,
            ),
            ReleaseReceiptEvidence::challenge_dispute(
                deterministic_root("challenge_dispute", "release-receipt"),
                config.challenge_window_close_height,
                config.dispute_window_close_height,
                &config,
            ),
            ReleaseReceiptEvidence::live_feed(
                deterministic_root("live_feed", "release-receipt"),
                4,
                35,
                &config,
            ),
            ReleaseReceiptEvidence::privacy(
                deterministic_root("privacy_bounds", "release-receipt"),
                3,
                &config,
            ),
        ];
        Self::evaluate(config, evidence).unwrap_or_else(|error| {
            let fallback_config = Config::devnet();
            let fallback_report = empty_report(&fallback_config, &error);
            Self {
                config: fallback_config,
                evidence: BTreeMap::new(),
                blockers: BTreeMap::new(),
                report: fallback_report,
            }
        })
    }

    pub fn devnet_clear_fixture() -> Self {
        let mut config = Config::devnet();
        config.observed_height = 10_200;
        config.production_release_allowed = true;
        let evidence = vec![
            ReleaseReceiptEvidence::wallet(
                deterministic_root("wallet_clear", "release-receipt"),
                deterministic_root("wallet_clear", "release-receipt"),
                16,
                &config,
            ),
            ReleaseReceiptEvidence::monero_broadcast(
                deterministic_root("monero_clear", "release-receipt"),
                deterministic_root("monero_clear", "release-receipt"),
                24,
                4,
                &config,
            ),
            ReleaseReceiptEvidence::pq_signature(
                deterministic_root("pq_signature_clear", "release-receipt"),
                deterministic_root("pq_signature_clear", "release-receipt"),
                256,
                true,
                2,
                &config,
            ),
            ReleaseReceiptEvidence::liquidity(
                deterministic_root("liquidity_clear", "release-receipt"),
                10_050,
                &config,
            ),
            ReleaseReceiptEvidence::reorg_watch(
                deterministic_root("reorg_clear", "release-receipt"),
                10_120,
                &config,
            ),
            ReleaseReceiptEvidence::challenge_dispute(
                deterministic_root("windows_clear", "release-receipt"),
                10_160,
                10_180,
                &config,
            ),
            ReleaseReceiptEvidence::live_feed(
                deterministic_root("live_feed_clear", "release-receipt"),
                6,
                5,
                &config,
            ),
            ReleaseReceiptEvidence::privacy(
                deterministic_root("privacy_clear", "release-receipt"),
                1,
                &config,
            ),
        ];
        Self::evaluate(config, evidence).unwrap_or_else(|error| {
            let fallback_config = Config::devnet();
            let fallback_report = empty_report(&fallback_config, &error);
            Self {
                config: fallback_config,
                evidence: BTreeMap::new(),
                blockers: BTreeMap::new(),
                report: fallback_report,
            }
        })
    }

    pub fn public_record(&self) -> Value {
        let evidence = self
            .evidence
            .values()
            .map(ReleaseReceiptEvidence::public_record)
            .collect::<Vec<_>>();
        let blockers = self
            .blockers
            .values()
            .map(ReleaseReceiptBlocker::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "evidence": evidence,
            "blockers": blockers,
            "report": self.report.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_receipt_runtime_state", &self.public_record())
    }

    pub fn acceptance_allowed(&self) -> bool {
        self.report.decision == ReleaseReceiptDecision::Acceptable
    }

    pub fn blocking_lanes(&self) -> Vec<ReleaseReceiptLane> {
        self.blockers
            .iter()
            .filter_map(|(lane, blocker)| {
                if blocker.release_blocking {
                    Some(*lane)
                } else {
                    None
                }
            })
            .collect()
    }
}

pub fn evaluate_release_receipt_blockers(
    config: Config,
    evidence_items: Vec<ReleaseReceiptEvidence>,
) -> MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerReleaseReceiptRuntimeResult<State> {
    State::evaluate(config, evidence_items)
}

pub fn devnet_blocked_fixture() -> State {
    State::devnet_blocked_fixture()
}

pub fn devnet_clear_fixture() -> State {
    State::devnet_clear_fixture()
}

pub fn devnet() -> State {
    State::devnet_blocked_fixture()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn derive_status(evidence: &ReleaseReceiptEvidence, config: &Config) -> ReleaseReceiptStatus {
    if evidence.expected_root.is_empty() || evidence.observed_root.is_empty() {
        return ReleaseReceiptStatus::Missing;
    }
    if requires_root_match(evidence.lane, config) && !evidence.root_matches {
        return ReleaseReceiptStatus::RootMismatch;
    }
    if evidence.freshness_age_blocks > evidence.freshness_limit_blocks {
        return ReleaseReceiptStatus::Stale;
    }

    match evidence.lane {
        ReleaseReceiptLane::WalletReceipt => {
            if evidence.confirmations < evidence.required_confirmations {
                ReleaseReceiptStatus::ConfirmationShortfall
            } else {
                ReleaseReceiptStatus::Clear
            }
        }
        ReleaseReceiptLane::MoneroBroadcastReceipt => {
            if evidence.confirmations < evidence.required_confirmations {
                ReleaseReceiptStatus::ConfirmationShortfall
            } else {
                ReleaseReceiptStatus::Clear
            }
        }
        ReleaseReceiptLane::PqSignatureReceipt => {
            if !evidence.signature_valid {
                ReleaseReceiptStatus::SignatureInvalid
            } else if evidence.security_bits < evidence.required_security_bits {
                ReleaseReceiptStatus::SignatureInvalid
            } else {
                ReleaseReceiptStatus::Clear
            }
        }
        ReleaseReceiptLane::LiquiditySettlement => {
            if evidence.measured_bps < evidence.required_bps {
                ReleaseReceiptStatus::LiquidityShortfall
            } else {
                ReleaseReceiptStatus::Clear
            }
        }
        ReleaseReceiptLane::ReorgWatch => {
            if evidence.finality_open || evidence.observed_height < evidence.close_height {
                ReleaseReceiptStatus::WatchWindowOpen
            } else {
                ReleaseReceiptStatus::Clear
            }
        }
        ReleaseReceiptLane::ChallengeDisputeWindows => {
            if evidence.finality_open
                || evidence.observed_height < config.challenge_window_close_height
            {
                ReleaseReceiptStatus::ChallengeWindowOpen
            } else if evidence.observed_height < config.dispute_window_close_height {
                ReleaseReceiptStatus::DisputeWindowOpen
            } else {
                ReleaseReceiptStatus::Clear
            }
        }
        ReleaseReceiptLane::LiveFeedObservation => {
            if evidence.quorum_count < evidence.required_quorum {
                ReleaseReceiptStatus::QuorumShortfall
            } else {
                ReleaseReceiptStatus::Clear
            }
        }
        ReleaseReceiptLane::PrivacyBounds => {
            if evidence.leakage_units > evidence.max_leakage_units {
                ReleaseReceiptStatus::PrivacyLeakageExceeded
            } else {
                ReleaseReceiptStatus::Clear
            }
        }
    }
}

fn requires_root_match(lane: ReleaseReceiptLane, config: &Config) -> bool {
    match lane {
        ReleaseReceiptLane::WalletReceipt => config.require_wallet_root_match,
        ReleaseReceiptLane::MoneroBroadcastReceipt => config.require_broadcast_root_match,
        ReleaseReceiptLane::PqSignatureReceipt => config.require_signature_transcript_match,
        ReleaseReceiptLane::LiquiditySettlement
        | ReleaseReceiptLane::ReorgWatch
        | ReleaseReceiptLane::ChallengeDisputeWindows
        | ReleaseReceiptLane::LiveFeedObservation
        | ReleaseReceiptLane::PrivacyBounds => true,
    }
}

fn derive_severity(lane: ReleaseReceiptLane, status: ReleaseReceiptStatus) -> BlockerSeverity {
    match status {
        ReleaseReceiptStatus::Clear => BlockerSeverity::Informational,
        ReleaseReceiptStatus::Missing | ReleaseReceiptStatus::RootMismatch => {
            BlockerSeverity::ReleaseStop
        }
        ReleaseReceiptStatus::SignatureInvalid | ReleaseReceiptStatus::PrivacyLeakageExceeded => {
            BlockerSeverity::ReleaseStop
        }
        ReleaseReceiptStatus::ConfirmationShortfall => match lane {
            ReleaseReceiptLane::WalletReceipt | ReleaseReceiptLane::MoneroBroadcastReceipt => {
                BlockerSeverity::Critical
            }
            _ => BlockerSeverity::Major,
        },
        ReleaseReceiptStatus::LiquidityShortfall => BlockerSeverity::Critical,
        ReleaseReceiptStatus::WatchWindowOpen
        | ReleaseReceiptStatus::ChallengeWindowOpen
        | ReleaseReceiptStatus::DisputeWindowOpen => BlockerSeverity::Major,
        ReleaseReceiptStatus::QuorumShortfall => BlockerSeverity::Critical,
        ReleaseReceiptStatus::Stale => BlockerSeverity::Critical,
        ReleaseReceiptStatus::HoldOpen => BlockerSeverity::Major,
    }
}

fn clearance_for(lane: ReleaseReceiptLane, status: ReleaseReceiptStatus) -> String {
    let action = match status {
        ReleaseReceiptStatus::Clear => "retain_receipt_record",
        ReleaseReceiptStatus::Missing => "supply_required_receipt",
        ReleaseReceiptStatus::RootMismatch => "reconcile_expected_and_observed_roots",
        ReleaseReceiptStatus::ConfirmationShortfall => "wait_for_required_confirmations",
        ReleaseReceiptStatus::SignatureInvalid => "replace_or_reauthorize_pq_signature_receipt",
        ReleaseReceiptStatus::LiquidityShortfall => "settle_liquidity_floor",
        ReleaseReceiptStatus::WatchWindowOpen => "wait_for_reorg_watch_close",
        ReleaseReceiptStatus::ChallengeWindowOpen => "wait_for_challenge_window_close",
        ReleaseReceiptStatus::DisputeWindowOpen => "wait_for_dispute_window_close",
        ReleaseReceiptStatus::QuorumShortfall => "restore_live_feed_quorum",
        ReleaseReceiptStatus::PrivacyLeakageExceeded => "tighten_privacy_bounds",
        ReleaseReceiptStatus::Stale => "refresh_receipt_evidence",
        ReleaseReceiptStatus::HoldOpen => "clear_release_hold",
    };
    format!("{}:{}", lane.as_str(), action)
}

fn build_report(
    config: &Config,
    evidence: &BTreeMap<ReleaseReceiptLane, ReleaseReceiptEvidence>,
    blockers: &BTreeMap<ReleaseReceiptLane, ReleaseReceiptBlocker>,
) -> ReleaseReceiptReport {
    let evidence_roots = evidence
        .values()
        .map(|item| item.state_root())
        .collect::<Vec<_>>();
    let blocker_roots = blockers
        .values()
        .map(|item| item.blocker_root.clone())
        .collect::<Vec<_>>();
    let lane_roots = ReleaseReceiptLane::all()
        .iter()
        .map(|lane| deterministic_root("release_receipt_lane", lane.as_str()))
        .collect::<Vec<_>>();
    let evidence_root = merkle_root(&evidence_roots);
    let blocker_root = merkle_root(&blocker_roots);
    let lane_root = merkle_root(&lane_roots);
    let config_root = config.state_root();
    let blocking_count = blockers
        .values()
        .filter(|blocker| blocker.release_blocking)
        .count();
    let highest_severity = blockers
        .values()
        .map(|blocker| blocker.severity)
        .max_by_key(|severity| severity.score())
        .unwrap_or(BlockerSeverity::Informational);
    let total_severity_score = blockers
        .values()
        .map(|blocker| blocker.severity.score())
        .sum::<u64>();
    let decision = if blocking_count == 0 && config.production_release_allowed {
        ReleaseReceiptDecision::Acceptable
    } else {
        ReleaseReceiptDecision::Blocked
    };
    let summary = json!({
        "release_receipt_id": config.release_receipt_id,
        "decision": decision.as_str(),
        "blocker_count": blockers.len(),
        "blocking_count": blocking_count,
        "highest_severity": highest_severity.as_str(),
        "total_severity_score": total_severity_score,
        "lane_root": lane_root,
        "evidence_root": evidence_root,
        "blocker_root": blocker_root,
        "config_root": config_root,
    });
    let summary_root = record_root("release_receipt_summary", &summary);
    let report_root = record_root("release_receipt_report", &summary);
    let report_id = id_root(
        "release_receipt_report_id",
        &config.release_receipt_id,
        &report_root,
    );
    ReleaseReceiptReport {
        report_id,
        decision,
        release_receipt_id: config.release_receipt_id.clone(),
        blocker_count: blockers.len(),
        blocking_count,
        highest_severity,
        total_severity_score,
        lane_root,
        evidence_root,
        blocker_root,
        summary_root,
        config_root,
        report_root,
    }
}

fn empty_report(config: &Config, error: &str) -> ReleaseReceiptReport {
    let config_root = config.state_root();
    let lane_root = merkle_root(&Vec::<String>::new());
    let evidence_root = merkle_root(&Vec::<String>::new());
    let blocker_root = merkle_root(&Vec::<String>::new());
    let summary = json!({
        "release_receipt_id": config.release_receipt_id,
        "decision": ReleaseReceiptDecision::Blocked.as_str(),
        "blocker_count": 0,
        "blocking_count": 1,
        "highest_severity": BlockerSeverity::ReleaseStop.as_str(),
        "total_severity_score": BlockerSeverity::ReleaseStop.score(),
        "lane_root": lane_root,
        "evidence_root": evidence_root,
        "blocker_root": blocker_root,
        "config_root": config_root,
        "evaluation_error": error,
    });
    let summary_root = record_root("release_receipt_empty_summary", &summary);
    let report_root = record_root("release_receipt_empty_report", &summary);
    let report_id = id_root(
        "release_receipt_empty_report_id",
        &config.release_receipt_id,
        &report_root,
    );
    ReleaseReceiptReport {
        report_id,
        decision: ReleaseReceiptDecision::Blocked,
        release_receipt_id: config.release_receipt_id.clone(),
        blocker_count: 0,
        blocking_count: 1,
        highest_severity: BlockerSeverity::ReleaseStop,
        total_severity_score: BlockerSeverity::ReleaseStop.score(),
        lane_root,
        evidence_root,
        blocker_root,
        summary_root,
        config_root,
        report_root,
    }
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_release_receipt_runtime.record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn id_root(kind: &str, label: &str, root: &str) -> String {
    domain_hash(
        "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_release_receipt_runtime.id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
            HashPart::Str(root),
        ],
        32,
    )
}

fn deterministic_root(kind: &str, seed: &str) -> String {
    domain_hash(
        "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_release_receipt_runtime.deterministic",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(seed),
        ],
        32,
    )
}
