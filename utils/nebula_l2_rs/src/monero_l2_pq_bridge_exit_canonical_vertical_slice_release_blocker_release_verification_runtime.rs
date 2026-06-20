use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerReleaseVerificationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_RELEASE_VERIFICATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-release-verification-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_RELEASE_VERIFICATION_RUNTIME_PROTOCOL_VERSION;
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-release-verification-devnet-v1";
pub const DEFAULT_RELEASE_WAVE_ID: &str = "release-verification-wave-devnet-v1";
pub const DEFAULT_EVALUATION_HEIGHT: u64 = 884_736;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerLane {
    WalletVerification,
    MoneroBroadcastVerification,
    PqCustodyVerification,
    LiquiditySettlementVerification,
    ChallengeDisputeWindows,
    LiveFeedFreshness,
    PrivacyLeakage,
    OperatorHalt,
    SecurityAuditGate,
}

impl BlockerLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletVerification => "wallet_verification",
            Self::MoneroBroadcastVerification => "monero_broadcast_verification",
            Self::PqCustodyVerification => "pq_custody_verification",
            Self::LiquiditySettlementVerification => "liquidity_settlement_verification",
            Self::ChallengeDisputeWindows => "challenge_dispute_windows",
            Self::LiveFeedFreshness => "live_feed_freshness",
            Self::PrivacyLeakage => "privacy_leakage",
            Self::OperatorHalt => "operator_halt",
            Self::SecurityAuditGate => "security_audit_gate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    Advisory,
    Degraded,
    ReleaseBlocking,
}

impl BlockerSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::Degraded => "degraded",
            Self::ReleaseBlocking => "release_blocking",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::ReleaseBlocking)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub vertical_slice_id: String,
    pub release_wave_id: String,
    pub evaluation_height: u64,
    pub fail_closed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_owned(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_owned(),
            release_wave_id: DEFAULT_RELEASE_WAVE_ID.to_owned(),
            evaluation_height: DEFAULT_EVALUATION_HEIGHT,
            fail_closed: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "vertical_slice_id": self.vertical_slice_id,
            "release_wave_id": self.release_wave_id,
            "evaluation_height": self.evaluation_height,
            "fail_closed": self.fail_closed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Blocker {
    pub lane: BlockerLane,
    pub severity: BlockerSeverity,
    pub reason: String,
    pub evidence_root: String,
}

impl Blocker {
    pub fn new(
        lane: BlockerLane,
        severity: BlockerSeverity,
        reason: impl Into<String>,
        evidence_seed: &str,
    ) -> Self {
        let lane_name = lane.as_str();
        let reason = reason.into();
        let evidence_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-EVIDENCE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(lane_name),
                HashPart::Str(severity.as_str()),
                HashPart::Str(&reason),
                HashPart::Str(evidence_seed),
            ],
            32,
        );

        Self {
            lane,
            severity,
            reason,
            evidence_root,
        }
    }

    pub fn blocks_release(&self) -> bool {
        self.severity.blocks_release()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "severity": self.severity.as_str(),
            "reason": self.reason,
            "evidence_root": self.evidence_root,
            "blocks_release": self.blocks_release(),
        })
    }

    pub fn blocker_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub blockers: Vec<Blocker>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            blockers: fail_closed_devnet_blockers(),
        }
    }

    pub fn release_blocked(&self) -> bool {
        self.config.fail_closed || self.blockers.iter().any(Blocker::blocks_release)
    }

    pub fn blocker_count(&self) -> usize {
        self.blockers.len()
    }

    pub fn blocking_count(&self) -> usize {
        self.blockers
            .iter()
            .filter(|blocker| blocker.blocks_release())
            .count()
    }

    pub fn blocker_roots(&self) -> Vec<String> {
        self.blockers.iter().map(Blocker::blocker_root).collect()
    }

    pub fn blocker_merkle_root(&self) -> String {
        let blocker_roots: Vec<Value> = self
            .blocker_roots()
            .into_iter()
            .map(Value::String)
            .collect();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-ROOT",
            &blocker_roots,
        )
    }

    pub fn public_record(&self) -> Value {
        let blocker_records: Vec<Value> =
            self.blockers.iter().map(Blocker::public_record).collect();
        let blocker_roots = self.blocker_roots();
        let blocker_merkle_root = self.blocker_merkle_root();

        json!({
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "release_blocked": self.release_blocked(),
            "blocker_count": self.blocker_count(),
            "blocking_count": self.blocking_count(),
            "blocker_merkle_root": blocker_merkle_root,
            "blocker_roots": blocker_roots,
            "blockers": blocker_records,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-RELEASE-VERIFICATION-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn require_release_clear(&self) -> Result<()> {
        if self.release_blocked() {
            Err(format!(
                "release verification blocked by {} active blockers",
                self.blocking_count()
            ))
        } else {
            Ok(())
        }
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

pub fn fail_closed_devnet_blockers() -> Vec<Blocker> {
    vec![
        Blocker::new(
            BlockerLane::WalletVerification,
            BlockerSeverity::ReleaseBlocking,
            "wallet exit transcript verification has not posted release-wave quorum",
            "wallet-verification-devnet-blocker",
        ),
        Blocker::new(
            BlockerLane::MoneroBroadcastVerification,
            BlockerSeverity::ReleaseBlocking,
            "monero broadcast proofs are not final across watcher receipts",
            "monero-broadcast-verification-devnet-blocker",
        ),
        Blocker::new(
            BlockerLane::PqCustodyVerification,
            BlockerSeverity::ReleaseBlocking,
            "post-quantum custody authority attestations remain incomplete",
            "pq-custody-verification-devnet-blocker",
        ),
        Blocker::new(
            BlockerLane::LiquiditySettlementVerification,
            BlockerSeverity::ReleaseBlocking,
            "liquidity settlement reserve and payout ledgers have not reconciled",
            "liquidity-settlement-verification-devnet-blocker",
        ),
        Blocker::new(
            BlockerLane::ChallengeDisputeWindows,
            BlockerSeverity::ReleaseBlocking,
            "challenge and dispute windows are still open for release candidates",
            "challenge-dispute-windows-devnet-blocker",
        ),
        Blocker::new(
            BlockerLane::LiveFeedFreshness,
            BlockerSeverity::ReleaseBlocking,
            "live feed freshness quorum is below the release verification threshold",
            "live-feed-freshness-devnet-blocker",
        ),
        Blocker::new(
            BlockerLane::PrivacyLeakage,
            BlockerSeverity::ReleaseBlocking,
            "privacy leakage review has unresolved disclosure findings",
            "privacy-leakage-devnet-blocker",
        ),
        Blocker::new(
            BlockerLane::OperatorHalt,
            BlockerSeverity::ReleaseBlocking,
            "operator halt switch remains armed for the release wave",
            "operator-halt-devnet-blocker",
        ),
        Blocker::new(
            BlockerLane::SecurityAuditGate,
            BlockerSeverity::ReleaseBlocking,
            "security audit gate has not accepted all required release evidence",
            "security-audit-gate-devnet-blocker",
        ),
    ]
}

pub fn clear_release_verification_fixture() -> State {
    State {
        config: Config {
            fail_closed: false,
            ..Config::devnet()
        },
        blockers: Vec::new(),
    }
}
